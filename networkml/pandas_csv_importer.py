import ipaddress
import functools
import warnings
from pandas.errors import DtypeWarning
# We are using converters to fix types, so mixed type warning from read_csv() is spurious.
warnings.simplefilter(action='ignore', category=DtypeWarning)
import pandas as pd
import netaddr


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
    'arp.opcode': (_safe_int, True),
    'eth.src': (_netaddr_packed, None),
    'eth.dst': (_netaddr_packed, None),
    'eth.type': (_hex_str, True),
    'frame.len': (_safe_int, True),
    'frame.time_epoch': (float, False),
    'frame.time_delta_displayed': (float, False),
    'frame.protocols': (_eth_protos, False),
    'icmp.code': (_safe_int, True),
    'gre.proto': (_hex_str, True),
    'ip.src': (_ipaddress_packed, None),
    'ip.src_host': (_ipaddress_packed, None),
    'ip.dst': (_ipaddress_packed, None),
    'ip.dst_host': (_ipaddress_packed, None),
    'ip.dsfield': (_hex_str, True),
    'ip.flags': (_hex_str, True),
    'ip.proto': (_safe_int, True),
    'ip.version': (_safe_int, True),
    'icmpv6.code': (_safe_int, True),
    'ipv6.src': (_ipaddress_packed, None),
    'ipv6.src_host': (_ipaddress_packed, None),
    'ipv6.dst': (_ipaddress_packed, None),
    'ipv6.dst_host': (_ipaddress_packed, None),
    'tcp.flags': (_hex_str, True),
    'tcp.srcport': (_safe_int, True),
    'tcp.dstport': (_safe_int, True),
    'udp.srcport': (_safe_int, True),
    'udp.dstport': (_safe_int, True),
    'vlan.etype': (_hex_str, True),
    'vlan.id': (_safe_int, True),
}
_WS_FIELDS_CONVERTERS = {field: field_info[0] for field, field_info in WS_FIELDS.items()}
_WS_FIELDS_NULLABLE_INT = {field for field, field_info in WS_FIELDS.items() if field_info[1]}
_REQUIRED_WS_FIELDS = {'eth.src', 'eth.dst', 'frame.len', 'frame.time_epoch', 'frame.time_delta_displayed'}


def import_csv(in_file):
    # We need converters, so we can't use dtypes parameter, and that results in an un-suppressable warning.
    csv_fields = set(pd.read_csv(in_file, index_col=0, nrows=0).columns.tolist())
    usecols = csv_fields.intersection(WS_FIELDS.keys())
    missingcols = set(WS_FIELDS.keys()) - csv_fields
    df = pd.read_csv(in_file, usecols=usecols, converters=_WS_FIELDS_CONVERTERS)
    for col in missingcols:
        df[col] = None
    for col in _REQUIRED_WS_FIELDS:
        assert df[col].count() > 0, 'required col %s is all null (not a PCAP CSV?)' % col
    # TODO: when pandas allows read_csv to infer nullable ints, we can use less memory on import.
    # https://github.com/pandas-dev/pandas/issues/2631
    # For now convert to nullable int after import.
    for col in _WS_FIELDS_NULLABLE_INT:
        df[col] = df[col].astype('Int64')
    return df
