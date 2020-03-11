from networkml.featurizers.funcs.host import Host


def test_tshark_input_mac():
    instance = Host()
    # 1 appears the most on both sides.
    # pytype: disable=attribute-error
    assert instance._tshark_input_mac(
        [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]) == (1, {1, 2, 99})


def test_select_mac_direction():
    rows = [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]
    instance = Host()
    # pytype: disable=attribute-error
    assert [{'eth.dst': 1, 'eth.src': 2}, {'eth.src': 1}, {'eth.src': 2}, {'eth.src': 99}] == list(instance._select_mac_direction(rows, output=False))
    assert [{'eth.dst': 2, 'eth.src': 1}, {'eth.dst': 99, 'eth.src': 1}, {'eth.src': 1}, {'eth.src': 2}, {'eth.src': 99}] == list(instance._select_mac_direction(rows, output=True))


def test_max_frame_time():
    instance = Host()
    assert instance.host_tshark_max_frame_time_in([
        {'eth.src': '0e:02:03:04:05:06', 'frame.time_epoch': 999},
        {'eth.src': '0e:02:03:04:05:06', 'frame.time_epoch': 1001}]) == [
                {'host_key': '0e:02:03:04:05:06', 'max_frame_time_in': 1001}]


def test_max_frame_len():
    instance = Host()
    assert instance.host_tshark_max_frame_len([{'eth.src': '0e:02:03:04:05:06', 'frame.len': 999}]) == [
        {'host_key': '0e:02:03:04:05:06', 'max_frame_len': 999}]


def test_ipversions():
    instance = Host()
    assert instance.host_tshark_ipv4([{'eth.src': '0e:02:03:04:05:06', 'ip.version': 4}]) == [
        {'host_key': '0e:02:03:04:05:06', 'IPv4': 1}]
    assert instance.host_tshark_ipv6([{'eth.src': '0e:02:03:04:05:06', 'ip.version': 6}]) == [
        {'host_key': '0e:02:03:04:05:06', 'IPv6': 1}]


def test_protocols():
    instance = Host()
    assert instance.host_tshark_last_protocols_array([{'eth.src': '0e:02:03:04:05:06', 'frame.protocols': 'eth:ethertype:ip:udp:db-lsp-disc:json'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'protocol_esp': 0, 'protocol_eth': 1, 'protocol_ip': 1, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 1}]
    assert instance.host_tshark_last_protocols_array([{'eth.src': '0e:02:03:04:05:06'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'protocol_esp': 0, 'protocol_eth': 0, 'protocol_ip': 0, 'protocol_gre': 0, 'protocol_ipv6': 0, 'protocol_tcp': 0, 'protocol_arp': 0, 'protocol_icmp': 0, 'other': 0}]


def test_non_ip():
    instance = Host()
    assert instance.host_tshark_non_ip([{'eth.src': '0e:02:03:04:05:06', 'eth.type': 99}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_non_ip': 1}]
    assert instance.host_tshark_non_ip([{'eth.src': '0e:02:03:04:05:06', 'eth.type': 0x00000800}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_non_ip': 0}]


def test_vlan_id():
    instance = Host()
    assert instance.host_tshark_vlan_id([{'eth.src': '0e:02:03:04:05:06', 'vlan.id': 999}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_vlan_id': 999}]


def test_ipx():
    instance = Host()
    assert instance.host_tshark_ipx([{'eth.src': '0e:02:03:04:05:06', 'eth.type': 0x8137}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ipx': 1}]
    assert instance.host_tshark_ipx([{'eth.src': '0e:02:03:04:05:06', 'eth.type': 0x800}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ipx': 0}]


def test_both_private_ip():
    instance = Host()
    assert instance.host_tshark_both_private_ip([{'eth.src': '0e:02:03:04:05:06', 'ip.src': '192.168.0.1', 'ip.dst': '10.10.1.1'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_both_private_ip': 1}]
    assert instance.host_tshark_both_private_ip([{'eth.src': '0e:02:03:04:05:06', 'ip.src': '192.168.0.1', 'ip.dst': '1.1.1.1'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_both_private_ip': 0}]


def test_ipv4_multicast():
    instance = Host()
    assert instance.host_tshark_ipv4_multicast([{'eth.src': '0e:02:03:04:05:06', 'ip.src': '192.168.0.1', 'ip.dst': '224.0.0.1'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ipv4_multicast': 1}]
    assert instance.host_tshark_ipv4_multicast([{'eth.src': '0e:02:03:04:05:06', 'ip.src': '192.168.0.1', 'ip.dst': '10.0.0.2'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ipv4_multicast': 0}]


def test_tcp_flags():
    instance = Host()
    assert instance.host_tshark_tcp_flags_out([{'eth.src': '0e:02:03:04:05:06', 'tcp.flags': 0x00000014}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_flags_ack_out': 1, 'tshark_tcp_flags_cwr_out': 0, 'tshark_tcp_flags_ece_out': 0,  'tshark_tcp_flags_fin_out': 0, 'tshark_tcp_flags_ns_out': 0, 'tshark_tcp_flags_psh_out': 0, 'tshark_tcp_flags_rst_out': 1, 'tshark_tcp_flags_syn_out': 0, 'tshark_tcp_flags_urg_out': 0}]
    assert instance.host_tshark_tcp_flags_in([{'eth.src': '0e:02:03:04:05:06','tcp.flags': 0x00000014}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_flags_ack_in': 1, 'tshark_tcp_flags_cwr_in': 0, 'tshark_tcp_flags_ece_in': 0,  'tshark_tcp_flags_fin_in': 0, 'tshark_tcp_flags_ns_in': 0, 'tshark_tcp_flags_psh_in': 0, 'tshark_tcp_flags_rst_in': 1, 'tshark_tcp_flags_syn_in': 0, 'tshark_tcp_flags_urg_in': 0}]


def test_ip_flags():
    instance = Host()
    assert instance.host_tshark_ip_flags_out([{'eth.src': '0e:02:03:04:05:06', 'ip.flags': 0x00004000}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ip_flags_rb_out': 0, 'tshark_ip_flags_df_out': 1, 'tshark_ip_flags_mf_out': 0}]
    assert instance.host_tshark_ip_flags_in([{'eth.src': '0e:02:03:04:05:06', 'ip.flags': 0x00004000}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ip_flags_rb_in': 0, 'tshark_ip_flags_df_in': 1, 'tshark_ip_flags_mf_in': 0}]


def test_ip_dsfield_flags():
    instance = Host()
    assert instance.host_tshark_ip_dsfield_out([{'eth.src': '0e:02:03:04:05:06', 'ip.dsfield': 0x000000c0}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ip_dsfield_ecn0_out': 0, 'tshark_ip_dsfield_ecn1_out': 0, 'tshark_ip_dsfield_dscp0_out': 0, 'tshark_ip_dsfield_dscp1_out': 0, 'tshark_ip_dsfield_dscp2_out': 0, 'tshark_ip_dsfield_dscp3_out': 0, 'tshark_ip_dsfield_dscp4_out': 1, 'tshark_ip_dsfield_dscp5_out': 1}]
    assert instance.host_tshark_ip_dsfield_in([{'eth.src': '0e:02:03:04:05:06', 'ip.dsfield': 0x000000c0}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_ip_dsfield_ecn0_in': 0, 'tshark_ip_dsfield_ecn1_in': 0, 'tshark_ip_dsfield_dscp0_in': 0, 'tshark_ip_dsfield_dscp1_in': 0, 'tshark_ip_dsfield_dscp2_in': 0, 'tshark_ip_dsfield_dscp3_in': 0, 'tshark_ip_dsfield_dscp4_in': 1, 'tshark_ip_dsfield_dscp5_in': 1}]


def test_tcp_priv_ports():
    instance = Host()
    assert instance.host_tshark_priv_tcp_ports_in([{'eth.src': '0e:02:03:04:05:06', 'tcp.srcport': 1025, 'tcp.dstport': 80}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_priv_port_161_in': 0, 'tshark_tcp_priv_port_67_in': 0, 'tshark_tcp_priv_port_68_in': 0, 'tshark_tcp_priv_port_69_in': 0, 'tshark_tcp_priv_port_631_in': 0, 'tshark_tcp_priv_port_137_in': 0, 'tshark_tcp_priv_port_138_in': 0, 'tshark_tcp_priv_port_139_in': 0, 'tshark_tcp_priv_port_110_in': 0, 'tshark_tcp_priv_port_143_in': 0, 'tshark_tcp_priv_port_80_in': 1, 'tshark_tcp_priv_port_53_in': 0, 'tshark_tcp_priv_port_22_in': 0, 'tshark_tcp_priv_port_23_in': 0, 'tshark_tcp_priv_port_88_in': 0, 'tshark_tcp_priv_port_25_in': 0, 'tshark_tcp_priv_port_443_in': 0, 'tshark_tcp_priv_port_123_in': 0, 'tshark_tcp_priv_port_other_in': 0}]
    assert instance.host_tshark_priv_tcp_ports_out([{'eth.src': '0e:02:03:04:05:06', 'tcp.srcport': 1025, 'tcp.dstport': 80}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_priv_port_161_out': 0, 'tshark_tcp_priv_port_67_out': 0, 'tshark_tcp_priv_port_68_out': 0, 'tshark_tcp_priv_port_69_out': 0, 'tshark_tcp_priv_port_631_out': 0, 'tshark_tcp_priv_port_137_out': 0, 'tshark_tcp_priv_port_138_out': 0, 'tshark_tcp_priv_port_139_out': 0, 'tshark_tcp_priv_port_110_out': 0, 'tshark_tcp_priv_port_143_out': 0, 'tshark_tcp_priv_port_80_out': 1, 'tshark_tcp_priv_port_53_out': 0, 'tshark_tcp_priv_port_22_out': 0, 'tshark_tcp_priv_port_23_out': 0, 'tshark_tcp_priv_port_88_out': 0, 'tshark_tcp_priv_port_25_out': 0, 'tshark_tcp_priv_port_443_out': 0, 'tshark_tcp_priv_port_123_out': 0, 'tshark_tcp_priv_port_other_out': 0}]



def test_udp_priv_ports():
    instance = Host()
    assert instance.host_tshark_priv_udp_ports_in([{'eth.src': '0e:02:03:04:05:06', 'udp.srcport': 1025, 'udp.dstport': 123}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_udp_priv_port_161_in': 0, 'tshark_udp_priv_port_67_in': 0, 'tshark_udp_priv_port_68_in': 0, 'tshark_udp_priv_port_69_in': 0, 'tshark_udp_priv_port_631_in': 0, 'tshark_udp_priv_port_137_in': 0, 'tshark_udp_priv_port_138_in': 0, 'tshark_udp_priv_port_139_in': 0, 'tshark_udp_priv_port_110_in': 0, 'tshark_udp_priv_port_143_in': 0, 'tshark_udp_priv_port_80_in': 0, 'tshark_udp_priv_port_53_in': 0, 'tshark_udp_priv_port_22_in': 0, 'tshark_udp_priv_port_23_in': 0, 'tshark_udp_priv_port_88_in': 0, 'tshark_udp_priv_port_25_in': 0, 'tshark_udp_priv_port_443_in': 0, 'tshark_udp_priv_port_123_in': 1, 'tshark_udp_priv_port_other_in': 0}]
    assert instance.host_tshark_priv_udp_ports_out([{'eth.src': '0e:02:03:04:05:06', 'udp.srcport': 1025, 'udp.dstport': 123}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_udp_priv_port_161_out': 0, 'tshark_udp_priv_port_67_out': 0, 'tshark_udp_priv_port_68_out': 0, 'tshark_udp_priv_port_69_out': 0, 'tshark_udp_priv_port_631_out': 0, 'tshark_udp_priv_port_137_out': 0, 'tshark_udp_priv_port_138_out': 0, 'tshark_udp_priv_port_139_out': 0, 'tshark_udp_priv_port_110_out': 0, 'tshark_udp_priv_port_143_out': 0, 'tshark_udp_priv_port_80_out': 0, 'tshark_udp_priv_port_53_out': 0, 'tshark_udp_priv_port_22_out': 0, 'tshark_udp_priv_port_23_out': 0, 'tshark_udp_priv_port_88_out': 0, 'tshark_udp_priv_port_25_out': 0, 'tshark_udp_priv_port_443_out': 0, 'tshark_udp_priv_port_123_out': 1, 'tshark_udp_priv_port_other_out': 0}]


def test_tcp_nonpriv_ports():
    instance = Host()
    assert instance.host_tshark_nonpriv_tcp_ports_in([{'eth.src': '0e:02:03:04:05:06', 'tcp.srcport': 1025, 'tcp.dstport': 9999}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_nonpriv_port_5349_in': 0, 'tshark_tcp_nonpriv_port_5222_in': 0, 'tshark_tcp_nonpriv_port_2375_in': 0, 'tshark_tcp_nonpriv_port_2376_in': 0, 'tshark_tcp_nonpriv_port_5353_in': 0, 'tshark_tcp_nonpriv_port_5354_in': 0, 'tshark_tcp_nonpriv_port_1900_in': 0, 'tshark_tcp_nonpriv_port_5357_in': 0, 'tshark_tcp_nonpriv_port_6653_in': 0, 'tshark_tcp_nonpriv_port_other_in': 1}]
    assert instance.host_tshark_nonpriv_tcp_ports_out([{'eth.src': '0e:02:03:04:05:06', 'tcp.srcport': 1025, 'tcp.dstport': 9999}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_tcp_nonpriv_port_5349_out': 0, 'tshark_tcp_nonpriv_port_5222_out': 0, 'tshark_tcp_nonpriv_port_2375_out': 0, 'tshark_tcp_nonpriv_port_2376_out': 0, 'tshark_tcp_nonpriv_port_5353_out': 0, 'tshark_tcp_nonpriv_port_5354_out': 0, 'tshark_tcp_nonpriv_port_1900_out': 0, 'tshark_tcp_nonpriv_port_5357_out': 0, 'tshark_tcp_nonpriv_port_6653_out': 0, 'tshark_tcp_nonpriv_port_other_out': 1}]



def test_wk_ip_protos():
    instance = Host()
    assert instance.host_tshark_wk_ip_protos([{'eth.src': '0e:02:03:04:05:06', 'tcp.something': 'whatever', 'udp.something': 'whatever', 'something.else': 'something', 'data.something': 'whatever'}]) == [
        {'host_key': '0e:02:03:04:05:06', 'tshark_wk_ip_proto_arp': 0, 'tshark_wk_ip_proto_other': 1, 'tshark_wk_ip_proto_icmpv6': 0, 'tshark_wk_ip_proto_icmp': 0, 'tshark_wk_ip_proto_tcp': 1, 'tshark_wk_ip_proto_udp': 1}]
