from networkml.featurizers.funcs.host import Host


def test_protocols():
    instance = Host()
    assert instance.tshark_last_protocols_array(
        [{'frame.protocols': 'eth:ethertype:ip:udp:db-lsp-disc:json'}]) == [
                {'protocol_db-lsp-disc': 1, 'protocol_ip': 1, 'protocol_json': 1, 'protocol_udp': 1, 'protocol_eth': 1}]
    assert instance.tshark_last_protocols_array([{}]) == [{'protocol_eth': 1}]
