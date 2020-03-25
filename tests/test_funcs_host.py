import operator
import ipaddress
from networkml.featurizers.funcs.host import Host, SessionHost
from networkml.featurizers.csv_to_features import WS_FIELDS

TEST_MAC = '0e:02:03:04:05:06'
TEST_MAC2 = '0e:02:03:04:05:07'
SESS_ROW = {'eth.src': TEST_MAC, 'ip.src': '127.0.0.1', 'eth.dst': TEST_MAC2, 'ip.dst': '127.0.0.2', 'tcp.srcport': 8080, 'tcp.dstport': 80}
HOST_ROW = {'eth.src': TEST_MAC, 'eth.dst': TEST_MAC2}


def _sort_output(output):
    return sorted(output, key=operator.itemgetter('host_key'))


def _make_rows_keys(rows, rows_keys):
    for row in rows:
        row.update(rows_keys)
        for row_key in row:
            assert row_key in WS_FIELDS
    return lambda: rows


def test_host_row_keys():
    instance = Host()
    assert instance._row_keys(HOST_ROW) == {TEST_MAC, TEST_MAC2}


def test_host_all_host_rows():
    instance = Host()
    rows = _make_rows_keys([{}], HOST_ROW)
    assert instance._all_host_rows(rows, rows)


def test_host_pyshark_ipv4():
    instance = Host()
    assert instance.pyshark_ipv4(
        lambda: [{'eth.src': TEST_MAC, 'layers': {'<IP Layer>': {}}}]) == [{'IPv4': 1}]


def test_host_pyshark_ipv6():
    instance = Host()
    assert instance.pyshark_ipv6(
        lambda: [{'eth.src': TEST_MAC, 'layers': {'<IPV6 Layer>': {}}}]) == [{'IPv6': 1}]


def test_host_tshark_input_mac():
    instance = Host()
    # 1 appears the most on both sides.
    # pytype: disable=attribute-error
    assert instance._tshark_input_mac(
        lambda: [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]) == (1, {1, 2, 99})


def test_host_select_mac_direction():
    rows = lambda: [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]
    instance = Host()
    # pytype: disable=attribute-error
    assert [{'eth.dst': 1, 'eth.src': 2}] == list(instance._select_mac_direction(rows, output=False)())
    assert [{'eth.dst': 2, 'eth.src': 1}, {'eth.dst': 99, 'eth.src': 1}] == list(instance._select_mac_direction(rows, output=True)())


def test_host_max_frame_time():
    instance = Host()
    rows = [{'frame.time_epoch': 999}, {'frame.time_epoch': 1001}]
    assert _sort_output(instance.host_tshark_max_frame_time_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'max_frame_time_in': 1001.0},
        {'host_key': TEST_MAC2, 'max_frame_time_in': 1001.0}
    ]


def test_host_max_frame_len():
    instance = Host()
    rows = [{'frame.len': 999}]
    assert _sort_output(instance.host_tshark_max_frame_len(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'max_frame_len': 999},
        {'host_key': TEST_MAC2, 'max_frame_len': 999}
    ]


def test_host_max_delta_time():
    instance = Host()
    rows = [{'frame.time_delta_displayed': 999}]
    assert _sort_output(instance.host_tshark_max_time_delta(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'max_time_delta': 999},
        {'host_key': TEST_MAC2, 'max_time_delta': 999}
    ]


def test_host_ipversions():
    instance = Host()
    rows = [{'ip.version': 4}]
    assert _sort_output(instance.host_tshark_ipv4(_make_rows_keys(rows, HOST_ROW))) == [
        {'IPv4': 1, 'host_key': TEST_MAC},
        {'IPv4': 1, 'host_key': TEST_MAC2}
    ]
    rows = [{'ip.version': 6}]
    assert _sort_output(instance.host_tshark_ipv6(_make_rows_keys(rows, HOST_ROW))) == [
        {'IPv6': 1, 'host_key': TEST_MAC},
        {'IPv6': 1, 'host_key': TEST_MAC2}
    ]


def test_host_protocols():
    instance = Host()
    rows = [{'frame.protocols': 'eth:ethertype:ip:udp:db-lsp-disc:json'}]
    assert _sort_output(instance.host_tshark_last_protocols_array(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'protocol_esp': 0, 'protocol_eth': 1, 'protocol_ip': 1, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 1},
        {'host_key': TEST_MAC2, 'protocol_esp': 0, 'protocol_eth': 1, 'protocol_ip': 1, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 1}
    ]
    rows = [{}]
    assert _sort_output(instance.host_tshark_last_protocols_array(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'protocol_esp': 0, 'protocol_eth': 0, 'protocol_ip': 0, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 0},
        {'host_key': TEST_MAC2, 'protocol_esp': 0, 'protocol_eth': 0, 'protocol_ip': 0, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 0}
    ]


def test_host_non_ip():
    instance = Host()
    rows = [{'eth.type': 99}]
    assert _sort_output(instance.host_tshark_non_ip(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_non_ip': 1},
        {'host_key': TEST_MAC2, 'tshark_non_ip': 1},
    ]
    rows = [{'eth.type': 0x800}]
    assert _sort_output(instance.host_tshark_non_ip(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_non_ip': 0},
        {'host_key': TEST_MAC2, 'tshark_non_ip': 0},
    ]


def test_host_vlan_id():
    instance = Host()
    rows = [{'vlan.id': 999}]
    assert _sort_output(instance.host_tshark_vlan_id(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_vlan_id': 999},
        {'host_key': TEST_MAC2, 'tshark_vlan_id': 999},
    ]


def test_host_ipx():
    instance = Host()
    rows = [{'eth.type': 0x8137}]
    assert _sort_output(instance.host_tshark_ipx(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ipx': 1},
        {'host_key': TEST_MAC2, 'tshark_ipx': 1},
    ]
    rows = [{'eth.type': 0x800}]
    assert _sort_output(instance.host_tshark_ipx(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ipx': 0},
        {'host_key': TEST_MAC2, 'tshark_ipx': 0},
    ]


def test_host_both_private_ip():
    instance = Host()
    assert instance.host_tshark_both_private_ip(
        lambda: [{'eth.src': TEST_MAC, 'ip.src': '192.168.0.1', 'ip.dst': '10.10.1.1'}]) == [
            {'host_key': TEST_MAC, 'tshark_both_private_ip': 1}]
    assert instance.host_tshark_both_private_ip(
        lambda: [{'eth.src': TEST_MAC, 'ip.src': '192.168.0.1', 'ip.dst': '1.1.1.1'}]) == [
            {'host_key': TEST_MAC, 'tshark_both_private_ip': 0}]


def test_host_ipv4_multicast():
    instance = Host()
    assert instance.host_tshark_ipv4_multicast(
        lambda: [{'eth.src': TEST_MAC, 'ip.src': '192.168.0.1', 'ip.dst': '224.0.0.1'}]) == [
            {'host_key': TEST_MAC, 'tshark_ipv4_multicast': 1}]
    assert instance.host_tshark_ipv4_multicast(
        lambda: [{'eth.src': TEST_MAC, 'ip.src': '192.168.0.1', 'ip.dst': '10.0.0.2'}]) == [
            {'host_key': TEST_MAC, 'tshark_ipv4_multicast': 0}]


def test_host_tcp_flags():
    instance = Host()
    rows = [{'tcp.flags': 0x00000014}]
    assert _sort_output(instance.host_tshark_tcp_flags_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_flags_ack_out': 0, 'tshark_tcp_flags_cwr_out': 0, 'tshark_tcp_flags_ece_out': 0,  'tshark_tcp_flags_fin_out': 0, 'tshark_tcp_flags_ns_out': 0, 'tshark_tcp_flags_psh_out': 0, 'tshark_tcp_flags_rst_out': 0, 'tshark_tcp_flags_syn_out': 0, 'tshark_tcp_flags_urg_out': 0},
        {'host_key': TEST_MAC2, 'tshark_tcp_flags_ack_out': 0, 'tshark_tcp_flags_cwr_out': 0, 'tshark_tcp_flags_ece_out': 0,  'tshark_tcp_flags_fin_out': 0, 'tshark_tcp_flags_ns_out': 0, 'tshark_tcp_flags_psh_out': 0, 'tshark_tcp_flags_rst_out': 0, 'tshark_tcp_flags_syn_out': 0, 'tshark_tcp_flags_urg_out': 0},
    ]
    assert _sort_output(instance.host_tshark_tcp_flags_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_flags_ack_in': 1, 'tshark_tcp_flags_cwr_in': 0, 'tshark_tcp_flags_ece_in': 0,  'tshark_tcp_flags_fin_in': 0, 'tshark_tcp_flags_ns_in': 0, 'tshark_tcp_flags_psh_in': 0, 'tshark_tcp_flags_rst_in': 1, 'tshark_tcp_flags_syn_in': 0, 'tshark_tcp_flags_urg_in': 0},
        {'host_key': TEST_MAC2, 'tshark_tcp_flags_ack_in': 1, 'tshark_tcp_flags_cwr_in': 0, 'tshark_tcp_flags_ece_in': 0,  'tshark_tcp_flags_fin_in': 0, 'tshark_tcp_flags_ns_in': 0, 'tshark_tcp_flags_psh_in': 0, 'tshark_tcp_flags_rst_in': 1, 'tshark_tcp_flags_syn_in': 0, 'tshark_tcp_flags_urg_in': 0},
    ]


def test_host_ip_flags():
    instance = Host()
    rows = [{'ip.flags': 0x00004000}]
    assert _sort_output(instance.host_tshark_ip_flags_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ip_flags_rb_out': 0, 'tshark_ip_flags_df_out': 0, 'tshark_ip_flags_mf_out': 0},
        {'host_key': TEST_MAC2, 'tshark_ip_flags_rb_out': 0, 'tshark_ip_flags_df_out': 0, 'tshark_ip_flags_mf_out': 0}
    ]
    assert _sort_output(instance.host_tshark_ip_flags_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ip_flags_rb_in': 0, 'tshark_ip_flags_df_in': 1, 'tshark_ip_flags_mf_in': 0},
        {'host_key': TEST_MAC2, 'tshark_ip_flags_rb_in': 0, 'tshark_ip_flags_df_in': 1, 'tshark_ip_flags_mf_in': 0}
    ]


def test_host_ip_dsfield_flags():
    instance = Host()
    rows = [{'ip.dsfield': 0x000000c0}]
    assert _sort_output(instance.host_tshark_ip_dsfield_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ip_dsfield_ecn0_out': 0, 'tshark_ip_dsfield_ecn1_out': 0, 'tshark_ip_dsfield_dscp0_out': 0, 'tshark_ip_dsfield_dscp1_out': 0, 'tshark_ip_dsfield_dscp2_out': 0, 'tshark_ip_dsfield_dscp3_out': 0, 'tshark_ip_dsfield_dscp4_out': 0, 'tshark_ip_dsfield_dscp5_out': 0},
        {'host_key': TEST_MAC2, 'tshark_ip_dsfield_ecn0_out': 0, 'tshark_ip_dsfield_ecn1_out': 0, 'tshark_ip_dsfield_dscp0_out': 0, 'tshark_ip_dsfield_dscp1_out': 0, 'tshark_ip_dsfield_dscp2_out': 0, 'tshark_ip_dsfield_dscp3_out': 0, 'tshark_ip_dsfield_dscp4_out': 0, 'tshark_ip_dsfield_dscp5_out': 0}
    ]
    assert _sort_output(instance.host_tshark_ip_dsfield_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_ip_dsfield_ecn0_in': 0, 'tshark_ip_dsfield_ecn1_in': 0, 'tshark_ip_dsfield_dscp0_in': 0, 'tshark_ip_dsfield_dscp1_in': 0, 'tshark_ip_dsfield_dscp2_in': 0, 'tshark_ip_dsfield_dscp3_in': 0, 'tshark_ip_dsfield_dscp4_in': 1, 'tshark_ip_dsfield_dscp5_in': 1},
        {'host_key': TEST_MAC2, 'tshark_ip_dsfield_ecn0_in': 0, 'tshark_ip_dsfield_ecn1_in': 0, 'tshark_ip_dsfield_dscp0_in': 0, 'tshark_ip_dsfield_dscp1_in': 0, 'tshark_ip_dsfield_dscp2_in': 0, 'tshark_ip_dsfield_dscp3_in': 0, 'tshark_ip_dsfield_dscp4_in': 1, 'tshark_ip_dsfield_dscp5_in': 1}]


def test_host_tcp_priv_ports():
    instance = Host()
    rows = [{'ip.src': '192.168.0.1', 'tcp.srcport': 1025, 'ip.dst': '192.168.0.2', 'tcp.dstport': 80}, {'ip.src': '192.168.0.1', 'tcp.srcport': 1025, 'ip.dst': '192.168.0.2', 'tcp.dstport': 25}]
    assert _sort_output(instance.host_tshark_priv_tcp_ports_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_priv_port_161_in': 0, 'tshark_tcp_priv_port_67_in': 0, 'tshark_tcp_priv_port_68_in': 0, 'tshark_tcp_priv_port_69_in': 0, 'tshark_tcp_priv_port_631_in': 0, 'tshark_tcp_priv_port_137_in': 0, 'tshark_tcp_priv_port_138_in': 0, 'tshark_tcp_priv_port_139_in': 0, 'tshark_tcp_priv_port_110_in': 0, 'tshark_tcp_priv_port_143_in': 0, 'tshark_tcp_priv_port_80_in': 1, 'tshark_tcp_priv_port_53_in': 0, 'tshark_tcp_priv_port_22_in': 0, 'tshark_tcp_priv_port_23_in': 0, 'tshark_tcp_priv_port_88_in': 0, 'tshark_tcp_priv_port_25_in': 1, 'tshark_tcp_priv_port_443_in': 0, 'tshark_tcp_priv_port_123_in': 0, 'tshark_tcp_priv_port_other_in': 0},
        {'host_key': TEST_MAC2, 'tshark_tcp_priv_port_161_in': 0, 'tshark_tcp_priv_port_67_in': 0, 'tshark_tcp_priv_port_68_in': 0, 'tshark_tcp_priv_port_69_in': 0, 'tshark_tcp_priv_port_631_in': 0, 'tshark_tcp_priv_port_137_in': 0, 'tshark_tcp_priv_port_138_in': 0, 'tshark_tcp_priv_port_139_in': 0, 'tshark_tcp_priv_port_110_in': 0, 'tshark_tcp_priv_port_143_in': 0, 'tshark_tcp_priv_port_80_in': 1, 'tshark_tcp_priv_port_53_in': 0, 'tshark_tcp_priv_port_22_in': 0, 'tshark_tcp_priv_port_23_in': 0, 'tshark_tcp_priv_port_88_in': 0, 'tshark_tcp_priv_port_25_in': 1, 'tshark_tcp_priv_port_443_in': 0, 'tshark_tcp_priv_port_123_in': 0, 'tshark_tcp_priv_port_other_in': 0},
    ]
    assert _sort_output(instance.host_tshark_priv_tcp_ports_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_priv_port_161_out': 0, 'tshark_tcp_priv_port_67_out': 0, 'tshark_tcp_priv_port_68_out': 0, 'tshark_tcp_priv_port_69_out': 0, 'tshark_tcp_priv_port_631_out': 0, 'tshark_tcp_priv_port_137_out': 0, 'tshark_tcp_priv_port_138_out': 0, 'tshark_tcp_priv_port_139_out': 0, 'tshark_tcp_priv_port_110_out': 0, 'tshark_tcp_priv_port_143_out': 0, 'tshark_tcp_priv_port_80_out': 0, 'tshark_tcp_priv_port_53_out': 0, 'tshark_tcp_priv_port_22_out': 0, 'tshark_tcp_priv_port_23_out': 0, 'tshark_tcp_priv_port_88_out': 0, 'tshark_tcp_priv_port_25_out': 0, 'tshark_tcp_priv_port_443_out': 0, 'tshark_tcp_priv_port_123_out': 0, 'tshark_tcp_priv_port_other_out': 0},
        {'host_key': TEST_MAC2, 'tshark_tcp_priv_port_161_out': 0, 'tshark_tcp_priv_port_67_out': 0, 'tshark_tcp_priv_port_68_out': 0, 'tshark_tcp_priv_port_69_out': 0, 'tshark_tcp_priv_port_631_out': 0, 'tshark_tcp_priv_port_137_out': 0, 'tshark_tcp_priv_port_138_out': 0, 'tshark_tcp_priv_port_139_out': 0, 'tshark_tcp_priv_port_110_out': 0, 'tshark_tcp_priv_port_143_out': 0, 'tshark_tcp_priv_port_80_out': 0, 'tshark_tcp_priv_port_53_out': 0, 'tshark_tcp_priv_port_22_out': 0, 'tshark_tcp_priv_port_23_out': 0, 'tshark_tcp_priv_port_88_out': 0, 'tshark_tcp_priv_port_25_out': 0, 'tshark_tcp_priv_port_443_out': 0, 'tshark_tcp_priv_port_123_out': 0, 'tshark_tcp_priv_port_other_out': 0}
    ]


def test_host_udp_priv_ports():
    instance = Host()
    rows = [{'udp.srcport': 1025, 'udp.dstport': 123}]
    assert _sort_output(instance.host_tshark_priv_udp_ports_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_udp_priv_port_161_in': 0, 'tshark_udp_priv_port_67_in': 0, 'tshark_udp_priv_port_68_in': 0, 'tshark_udp_priv_port_69_in': 0, 'tshark_udp_priv_port_631_in': 0, 'tshark_udp_priv_port_137_in': 0, 'tshark_udp_priv_port_138_in': 0, 'tshark_udp_priv_port_139_in': 0, 'tshark_udp_priv_port_110_in': 0, 'tshark_udp_priv_port_143_in': 0, 'tshark_udp_priv_port_80_in': 0, 'tshark_udp_priv_port_53_in': 0, 'tshark_udp_priv_port_22_in': 0, 'tshark_udp_priv_port_23_in': 0, 'tshark_udp_priv_port_88_in': 0, 'tshark_udp_priv_port_25_in': 0, 'tshark_udp_priv_port_443_in': 0, 'tshark_udp_priv_port_123_in': 1, 'tshark_udp_priv_port_other_in': 0},
        {'host_key': TEST_MAC2, 'tshark_udp_priv_port_161_in': 0, 'tshark_udp_priv_port_67_in': 0, 'tshark_udp_priv_port_68_in': 0, 'tshark_udp_priv_port_69_in': 0, 'tshark_udp_priv_port_631_in': 0, 'tshark_udp_priv_port_137_in': 0, 'tshark_udp_priv_port_138_in': 0, 'tshark_udp_priv_port_139_in': 0, 'tshark_udp_priv_port_110_in': 0, 'tshark_udp_priv_port_143_in': 0, 'tshark_udp_priv_port_80_in': 0, 'tshark_udp_priv_port_53_in': 0, 'tshark_udp_priv_port_22_in': 0, 'tshark_udp_priv_port_23_in': 0, 'tshark_udp_priv_port_88_in': 0, 'tshark_udp_priv_port_25_in': 0, 'tshark_udp_priv_port_443_in': 0, 'tshark_udp_priv_port_123_in': 1, 'tshark_udp_priv_port_other_in': 0}
    ]
    assert _sort_output(instance.host_tshark_priv_udp_ports_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_udp_priv_port_161_out': 0, 'tshark_udp_priv_port_67_out': 0, 'tshark_udp_priv_port_68_out': 0, 'tshark_udp_priv_port_69_out': 0, 'tshark_udp_priv_port_631_out': 0, 'tshark_udp_priv_port_137_out': 0, 'tshark_udp_priv_port_138_out': 0, 'tshark_udp_priv_port_139_out': 0, 'tshark_udp_priv_port_110_out': 0, 'tshark_udp_priv_port_143_out': 0, 'tshark_udp_priv_port_80_out': 0, 'tshark_udp_priv_port_53_out': 0, 'tshark_udp_priv_port_22_out': 0, 'tshark_udp_priv_port_23_out': 0, 'tshark_udp_priv_port_88_out': 0, 'tshark_udp_priv_port_25_out': 0, 'tshark_udp_priv_port_443_out': 0, 'tshark_udp_priv_port_123_out': 0, 'tshark_udp_priv_port_other_out': 0},
        {'host_key': TEST_MAC2, 'tshark_udp_priv_port_161_out': 0, 'tshark_udp_priv_port_67_out': 0, 'tshark_udp_priv_port_68_out': 0, 'tshark_udp_priv_port_69_out': 0, 'tshark_udp_priv_port_631_out': 0, 'tshark_udp_priv_port_137_out': 0, 'tshark_udp_priv_port_138_out': 0, 'tshark_udp_priv_port_139_out': 0, 'tshark_udp_priv_port_110_out': 0, 'tshark_udp_priv_port_143_out': 0, 'tshark_udp_priv_port_80_out': 0, 'tshark_udp_priv_port_53_out': 0, 'tshark_udp_priv_port_22_out': 0, 'tshark_udp_priv_port_23_out': 0, 'tshark_udp_priv_port_88_out': 0, 'tshark_udp_priv_port_25_out': 0, 'tshark_udp_priv_port_443_out': 0, 'tshark_udp_priv_port_123_out': 0, 'tshark_udp_priv_port_other_out': 0}
    ]


def test_host_tcp_nonpriv_ports():
    instance = Host()
    rows = [{'tcp.srcport': 1025, 'tcp.dstport': 9999}]
    assert _sort_output(instance.host_tshark_nonpriv_tcp_ports_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_nonpriv_port_5349_in': 0, 'tshark_tcp_nonpriv_port_5222_in': 0, 'tshark_tcp_nonpriv_port_2375_in': 0, 'tshark_tcp_nonpriv_port_2376_in': 0, 'tshark_tcp_nonpriv_port_5353_in': 0, 'tshark_tcp_nonpriv_port_5354_in': 0, 'tshark_tcp_nonpriv_port_1900_in': 0, 'tshark_tcp_nonpriv_port_5357_in': 0, 'tshark_tcp_nonpriv_port_6653_in': 0, 'tshark_tcp_nonpriv_port_other_in': 1},
        {'host_key': TEST_MAC2, 'tshark_tcp_nonpriv_port_5349_in': 0, 'tshark_tcp_nonpriv_port_5222_in': 0, 'tshark_tcp_nonpriv_port_2375_in': 0, 'tshark_tcp_nonpriv_port_2376_in': 0, 'tshark_tcp_nonpriv_port_5353_in': 0, 'tshark_tcp_nonpriv_port_5354_in': 0, 'tshark_tcp_nonpriv_port_1900_in': 0, 'tshark_tcp_nonpriv_port_5357_in': 0, 'tshark_tcp_nonpriv_port_6653_in': 0, 'tshark_tcp_nonpriv_port_other_in': 1}
    ]
    assert _sort_output(instance.host_tshark_nonpriv_tcp_ports_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_tcp_nonpriv_port_5349_out': 0, 'tshark_tcp_nonpriv_port_5222_out': 0, 'tshark_tcp_nonpriv_port_2375_out': 0, 'tshark_tcp_nonpriv_port_2376_out': 0, 'tshark_tcp_nonpriv_port_5353_out': 0, 'tshark_tcp_nonpriv_port_5354_out': 0, 'tshark_tcp_nonpriv_port_1900_out': 0, 'tshark_tcp_nonpriv_port_5357_out': 0, 'tshark_tcp_nonpriv_port_6653_out': 0, 'tshark_tcp_nonpriv_port_other_out': 0},
        {'host_key': TEST_MAC2, 'tshark_tcp_nonpriv_port_5349_out': 0, 'tshark_tcp_nonpriv_port_5222_out': 0, 'tshark_tcp_nonpriv_port_2375_out': 0, 'tshark_tcp_nonpriv_port_2376_out': 0, 'tshark_tcp_nonpriv_port_5353_out': 0, 'tshark_tcp_nonpriv_port_5354_out': 0, 'tshark_tcp_nonpriv_port_1900_out': 0, 'tshark_tcp_nonpriv_port_5357_out': 0, 'tshark_tcp_nonpriv_port_6653_out': 0, 'tshark_tcp_nonpriv_port_other_out': 0}
    ]


def test_host_udp_nonpriv_ports():
    instance = Host()
    rows = [{'udp.srcport': 1025, 'udp.dstport': 9999}]
    assert _sort_output(instance.host_tshark_nonpriv_udp_ports_in(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_udp_nonpriv_port_5349_in': 0, 'tshark_udp_nonpriv_port_5222_in': 0, 'tshark_udp_nonpriv_port_2375_in': 0, 'tshark_udp_nonpriv_port_2376_in': 0, 'tshark_udp_nonpriv_port_5353_in': 0, 'tshark_udp_nonpriv_port_5354_in': 0, 'tshark_udp_nonpriv_port_1900_in': 0, 'tshark_udp_nonpriv_port_5357_in': 0, 'tshark_udp_nonpriv_port_6653_in': 0, 'tshark_udp_nonpriv_port_other_in': 1},
        {'host_key': TEST_MAC2, 'tshark_udp_nonpriv_port_5349_in': 0, 'tshark_udp_nonpriv_port_5222_in': 0, 'tshark_udp_nonpriv_port_2375_in': 0, 'tshark_udp_nonpriv_port_2376_in': 0, 'tshark_udp_nonpriv_port_5353_in': 0, 'tshark_udp_nonpriv_port_5354_in': 0, 'tshark_udp_nonpriv_port_1900_in': 0, 'tshark_udp_nonpriv_port_5357_in': 0, 'tshark_udp_nonpriv_port_6653_in': 0, 'tshark_udp_nonpriv_port_other_in': 1}
    ]
    assert _sort_output(instance.host_tshark_nonpriv_udp_ports_out(_make_rows_keys(rows, HOST_ROW))) == [
        {'host_key': TEST_MAC, 'tshark_udp_nonpriv_port_5349_out': 0, 'tshark_udp_nonpriv_port_5222_out': 0, 'tshark_udp_nonpriv_port_2375_out': 0, 'tshark_udp_nonpriv_port_2376_out': 0, 'tshark_udp_nonpriv_port_5353_out': 0, 'tshark_udp_nonpriv_port_5354_out': 0, 'tshark_udp_nonpriv_port_1900_out': 0, 'tshark_udp_nonpriv_port_5357_out': 0, 'tshark_udp_nonpriv_port_6653_out': 0, 'tshark_udp_nonpriv_port_other_out': 0},
        {'host_key': TEST_MAC2, 'tshark_udp_nonpriv_port_5349_out': 0, 'tshark_udp_nonpriv_port_5222_out': 0, 'tshark_udp_nonpriv_port_2375_out': 0, 'tshark_udp_nonpriv_port_2376_out': 0, 'tshark_udp_nonpriv_port_5353_out': 0, 'tshark_udp_nonpriv_port_5354_out': 0, 'tshark_udp_nonpriv_port_1900_out': 0, 'tshark_udp_nonpriv_port_5357_out': 0, 'tshark_udp_nonpriv_port_6653_out': 0, 'tshark_udp_nonpriv_port_other_out': 0}
    ]


def test_host_wk_ip_protos():
    instance = Host()
    assert instance.host_tshark_wk_ip_protos(
        lambda: [{'eth.src': TEST_MAC, 'tcp.something': 'whatever', 'udp.something': 'whatever', 'something.else': 'something', 'data.something': 'whatever'}]) == [
            {'host_key': TEST_MAC, 'tshark_wk_ip_proto_arp': 0, 'tshark_wk_ip_proto_other': 1, 'tshark_wk_ip_proto_icmpv6': 0, 'tshark_wk_ip_proto_icmp': 0, 'tshark_wk_ip_proto_tcp': 1, 'tshark_wk_ip_proto_udp': 1}]


def test_session_row_keys():
    instance = SessionHost()
    assert instance._row_keys(SESS_ROW) == {
        ('0e:02:03:04:05:06', 'tcp', str(ipaddress.IPv4Address('127.0.0.1')), '8080', '0e:02:03:04:05:07', str(ipaddress.IPv4Address('127.0.0.2')), '80'),
        ('0e:02:03:04:05:07', 'tcp', str(ipaddress.IPv4Address('127.0.0.2')), '80', '0e:02:03:04:05:06', str(ipaddress.IPv4Address('127.0.0.1')), '8080')
    }


def test_host_all_host_rows():
    instance = SessionHost()
    rows = _make_rows_keys([{}], SESS_ROW)
    assert instance._all_host_rows(rows, rows)


def test_session_max_frame_time():
    rows = [{'frame.time_epoch': 999}, {'frame.time_epoch': 1001}]
    instance = SessionHost()
    assert _sort_output(instance.sessionhost_tshark_max_frame_time_in(_make_rows_keys(rows, SESS_ROW))) == [
        {'host_key': TEST_MAC, 'max_frame_time_in': 1001.0},
        {'host_key': TEST_MAC2, 'max_frame_time_in': 1001.0}
    ]
    assert _sort_output(instance.sessionhost_tshark_max_frame_time_out(_make_rows_keys(rows, SESS_ROW))) == [
        {'host_key': TEST_MAC, 'max_frame_time_out': 0},
        {'host_key': TEST_MAC2, 'max_frame_time_out': 0}
    ]
