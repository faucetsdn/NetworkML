import functools
import ipaddress
import warnings

import netaddr
import pandas as pd
from pandas.errors import DtypeWarning
# We are using converters to fix types, so mixed type warning from read_csv() is spurious.
warnings.simplefilter(action='ignore', category=DtypeWarning)


@functools.lru_cache()
def _ipaddress_packed(val):
    if len(val) > 0:
        return int(ipaddress.ip_address(val))
    return None


@functools.lru_cache()
def _netaddr_packed(val):
    if len(val) > 0:
        return int(netaddr.EUI(val))
    return None


def _hex_str(val):
    if len(val) > 0:
        assert val.startswith('0x'), val
        return int(val, 16)
    return None


def _safe_int(val):
    if len(val) > 0:
        return int(val)
    return None


def _eth_protos(val):
    return ':'.join([i for i in val.split(':') if i != 'ethertype'])


WS_FIELDS = {
    'arp.opcode': (_safe_int, 8),
    'eth.src': (_netaddr_packed, None),
    'eth.dst': (_netaddr_packed, None),
    'eth.type': (_hex_str, 16),
    'frame.len': (_safe_int, 32),
    'frame.time_epoch': (float, None),
    'frame.time_delta_displayed': (float, None),
    'frame.protocols': (_eth_protos, None),
    'icmp.code': (_safe_int, 8),
    'gre.proto': (_hex_str, 8),
    'ip.src': (_ipaddress_packed, None),
    'ip.src_host': (_ipaddress_packed, None),
    'ip.dst': (_ipaddress_packed, None),
    'ip.dst_host': (_ipaddress_packed, None),
    'ip.dsfield': (_hex_str, 8),
    'ip.flags': (_hex_str, 16),
    'ip.proto': (_safe_int, 8),
    'ip.version': (_safe_int, 8),
    'icmpv6.code': (_safe_int, 8),
    'ipv6.src': (_ipaddress_packed, None),
    'ipv6.src_host': (_ipaddress_packed, None),
    'ipv6.dst': (_ipaddress_packed, None),
    'ipv6.dst_host': (_ipaddress_packed, None),
    'tcp.flags': (_hex_str, 16),
    'tcp.srcport': (_safe_int, 16),
    'tcp.dstport': (_safe_int, 16),
    'udp.srcport': (_safe_int, 16),
    'udp.dstport': (_safe_int, 16),
    'vlan.etype': (_hex_str, 16),
    'vlan.id': (_safe_int, 16),
}
_WS_FIELDS_CONVERTERS = {field: field_info[0]
                         for field, field_info in WS_FIELDS.items()}
_WS_FIELDS_NULLABLE_INT = {field: 'UInt%s' % field_info[1] for field, field_info in WS_FIELDS.items(
) if isinstance(field_info[1], int)}
_REQUIRED_WS_FIELDS = {'eth.src', 'eth.dst', 'frame.len',
                       'frame.time_epoch', 'frame.time_delta_displayed'}


def recast_df(df):
    # TODO: when pandas allows read_csv to infer nullable ints, we can use less memory on import.
    # https://github.com/pandas-dev/pandas/issues/2631
    # For now convert to nullable int after import.
    for col, typestr in _WS_FIELDS_NULLABLE_INT.items():
        try:
            df[col] = df[col].astype(typestr)
        except TypeError:
            raise TypeError('cannot cast %s to %s: %u' %
                            (col, typestr, df[col].max()))
    return df


def import_csv(in_file):
    # We need converters, so we can't use dtypes parameter, and that results in an un-suppressable warning.
    csv_fields = set(pd.read_csv(
        in_file, index_col=0, nrows=0).columns.tolist())
    usecols = csv_fields.intersection(WS_FIELDS.keys())
    missingcols = set(WS_FIELDS.keys()) - csv_fields
    df = pd.read_csv(in_file, usecols=usecols,
                     converters=_WS_FIELDS_CONVERTERS)
    for col in missingcols:
        df[col] = None
    for col in _REQUIRED_WS_FIELDS:
        assert df[col].count(
        ) > 0, 'required col %s is all null (not a PCAP CSV?)' % col
    return recast_df(df)
