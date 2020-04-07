import ipaddress
import pandas as pd
import netaddr
from networkml.featurizers.funcs.host import HostBase, Host, SessionHost
from networkml.pandas_csv_importer import WS_FIELDS, recast_df


def nan_row_dict(defaults):
    row = {field: None for field in WS_FIELDS}
    row.update(defaults)
    return pd.Series(row)


def test_get_ips():
    instance = HostBase()
    for ipv, ipb, srcip, dstip, ip_flags in (
             (4, 'ip', ipaddress.ip_address('192.168.0.1'), ipaddress.ip_address('192.168.0.2'), (1, 0)),
             (6, 'ipv6', ipaddress.ip_address('fc01::1'), ipaddress.ip_address('fc01::2'), (1, 0)),
             (4, 'ip', ipaddress.ip_address('192.168.0.1'), ipaddress.ip_address('8.8.8.8'), (0, 0)),
             (6, 'ipv6', ipaddress.ip_address('fc01::1'), ipaddress.ip_address('2001:4860:4860::8888'), (0, 0)),
             (4, 'ip', ipaddress.ip_address('192.168.0.1'), ipaddress.ip_address('224.0.0.1'), (0, 1))):
        row = nan_row_dict({'ip.version': ipv, '%s.src' % ipb: str(int(srcip)), '%s.dst' % ipb: str(int(dstip))})
        assert instance._get_src_ip(row) == srcip
        assert instance._get_dst_ip(row) == dstip
        assert instance._df_ip_flags(srcip, dstip) == ip_flags


def test_macs():
    instance = HostBase()
    assert instance._is_unicast(int(netaddr.EUI('0e:00:00:00:00:01'))) == True
    assert instance._is_unicast(int(netaddr.EUI('ff:ff:ff:ff:ff:ff'))) == False


def test_flags():
    instance = HostBase()
    mac_df = pd.DataFrame.from_dict({'test_col': [1, 2, 4]})
    assert instance._get_flags(mac_df, 'test_col', {0: 'foo', 1: 'baz', 2: 'blah'}, suffix=None, field_name=None) == {
        'tshark_test_col_foo': 1, 'tshark_test_col_baz': 1, 'tshark_test_col_blah': 1}
    mac_df = pd.DataFrame.from_dict({'test_col': [1, 0, 4]})
    assert instance._get_flags(mac_df, 'test_col', {0: 'foo', 1: 'baz', 2: 'blah'}, suffix=None, field_name=None) == {
        'tshark_test_col_foo': 1, 'tshark_test_col_baz': 0, 'tshark_test_col_blah': 1}


def test_lowest_ip_proto_port():
    instance = HostBase()
    test_data = {field: None for field in WS_FIELDS}
    test_data.update({
        'tcp.srcport': 99,
        'tcp.dstport': 100,
    })
    mac_df = recast_df(pd.DataFrame([test_data]))
    assert instance._lowest_ip_proto_port(mac_df, 'tcp') == {99}


def test_tshark_ports():
    instance = HostBase()
    for test_ports, test_output in (
            ({'tcp.srcport': 22, 'tcp.dstport': 1025},  {'tshark_tcp_priv_port_22_in'}),
            ({'tcp.srcport': 1025, 'tcp.dstport': 1025},  {'tshark_tcp_nonpriv_port_other_in'})):
        test_data = {field: None for field in WS_FIELDS}
        test_data.update(test_ports)
        mac_df = recast_df(pd.DataFrame([test_data]))
        ports = instance._tshark_ports('in', mac_df)
        assert test_output == {col for col, val in ports.items() if val == 1}


def test_ip_versions():
    instance = HostBase()
    test_data = {field: None for field in WS_FIELDS}
    test_data.update({'ip.version': 4})
    mac_df = recast_df(pd.DataFrame([test_data]))
    assert instance._tshark_ipversions(mac_df) == {'tshark_ipv4': 1, 'tshark_ipv6': 0}


def test_non_ip():
    instance = HostBase()
    for eth_type, test_output in (
            (1, {'tshark_ipx': 0, 'tshark_nonip': 1}),
            (0x8137, {'tshark_ipx': 1, 'tshark_nonip': 1}),
            (0x800, {'tshark_ipx': 0, 'tshark_nonip': 0})):
        test_data = {field: None for field in WS_FIELDS}
        test_data.update({'eth.type': eth_type})
        mac_df = recast_df(pd.DataFrame([test_data]))
        assert instance._tshark_non_ip(mac_df) == test_output


def test_vlan_id():
    instance = HostBase()
    test_data = {field: None for field in WS_FIELDS}
    mac_df = recast_df(pd.DataFrame([test_data]))
    assert instance._tshark_vlan_id(mac_df) == {'tshark_tagged_vlan': 0}
    test_data.update({'vlan.id': 99})
    mac_df = recast_df(pd.DataFrame([test_data]))
    assert instance._tshark_vlan_id(mac_df) == {'tshark_tagged_vlan': 1}


def test_smoke_calc_cols():
    instance = HostBase()
    test_data = {field: None for field in WS_FIELDS}
    eth_src = '0e:00:00:00:00:01'
    eth_src_int = int(netaddr.EUI(eth_src))
    test_data.update({
        'ip.version': 4,
        'eth.src': eth_src_int,
        'eth.dst': eth_src_int,
        '_srcip': '192.168.0.1',
        '_dstip': '192.168.0.2',
    })
    mac_df = recast_df(pd.DataFrame([test_data]))
    assert instance._calc_cols(eth_src_int, mac_df)


def test_host_keys():
    test_data = {field: None for field in WS_FIELDS}
    eth_src = '0e:00:00:00:00:01'
    eth_src_int = int(netaddr.EUI(eth_src))
    src_ip = ipaddress.ip_address('192.168.0.1')
    dst_ip = ipaddress.ip_address('192.168.0.2')
    test_data.update({
        'ip.version': 4,
        'eth.src': eth_src_int,
        'eth.dst': eth_src_int,
        'ip.src': str(int(src_ip)),
        'ip.dst': str(int(dst_ip)),
        'tcp.srcport': 999,
        'tcp.dstport': 1001,
        'frame.protocols': 'eth:ip',
    })
    row = nan_row_dict(test_data)
    instance = Host()
    assert instance._host_key(row)[1:] == (str(src_ip), str(dst_ip), 1, 0, 1)
    instance = SessionHost()
    assert instance._host_key(row)[1:] == (str(src_ip), str(dst_ip), 1, 0, 1)
