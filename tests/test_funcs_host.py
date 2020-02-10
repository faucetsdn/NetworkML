from networkml.featurizers.funcs.host import Host


def test_protocols():
    instance = Host()
    assert instance.tshark_last_protocols_array(
        [{'frame.protocols': 'eth:ethertype:ip:udp:db-lsp-disc:json'}]) == [
                {'protocol_db-lsp-disc': 1, 'protocol_ip': 1, 'protocol_json': 1, 'protocol_udp': 1, 'protocol_eth': 1}]
    assert instance.tshark_last_protocols_array([{}]) == [{}]


def test_non_ip():
    instance = Host()
    assert instance.tshark_non_ip([{'eth.type': 99}]) == [{'tshark_non_ip': 1}]
    assert instance.tshark_non_ip([{'eth.type': 0x00000800}]) == [{'tshark_non_ip': 0}]


def test_both_private_ip():
    instance = Host()
    assert instance.tshark_both_private_ip([{'ip.src': '192.168.0.1', 'ip.dst': '10.10.1.1'}]) == [
        {'tshark_both_private_ip': 1}]
    assert instance.tshark_both_private_ip([{'ip.src': '192.168.0.1', 'ip.dst': '1.1.1.1'}]) == [
        {'tshark_both_private_ip': 0}]


def test_ipv4_multicast():
    instance = Host()
    assert instance.tshark_ipv4_multicast([{'ip.src': '192.168.0.1', 'ip.dst': '224.0.0.1'}]) == [
        {'tshark_ipv4_multicast': 1}]
    assert instance.tshark_ipv4_multicast([{'ip.src': '192.168.0.1', 'ip.dst': '10.0.0.2'}]) == [
        {'tshark_ipv4_multicast': 0}]


def test_tcp_priv_ports():
    instance = Host()
    assert instance.tshark_priv_tcp_ports([{'tcp.srcport': 1025, 'tcp.dstport': 80}]) == [
        {'tshark_tcp_priv_port_80': 1}]


def test_tcp_nonpriv_ports():
    instance = Host()
    assert instance.tshark_nonpriv_tcp_ports([{'tcp.srcport': 1025, 'tcp.dstport': 9999}]) == [
        {'tshark_nonpriv_tcp_ports': 1}]


def test_wk_ip_protos():
    instance = Host()
    assert instance.tshark_wk_ip_protos([{'tcp': {}}, {'udp': {}}, {'somethingelse': {}}]) == [
        {'tshark_wk_ip_proto_udp': 1, 'tshark_wk_ip_proto_other': 1, 'tshark_wk_ip_proto_tcp': 1}]

