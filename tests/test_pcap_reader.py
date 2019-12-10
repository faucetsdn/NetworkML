import datetime
import networkml.parsers.pcap.reader


def test_packetizer():
    packet_dict = networkml.parsers.pcap.reader.packetizer(
        'tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap')
    assert len(packet_dict) == 14169
    packet_list = list(packet_dict.items())
    head, data = packet_list[0]
    # We have to drop date from comparison because reader.py doesn't use UTC consistently.
    # Migrate to UTC in the future.
    _, key1, key2 = head
    assert ('192.168.3.131:57011', '72.14.213.138:80') == (key1, key2)
    assert 1994 == len(data)
    assert '001a8c15f9804061' == data[:16]
    head, data = packet_list[-1]
    _, key1, key2 = head
    assert ('192.168.3.131:17500', '192.168.3.255:17500') == (key1, key2)
    assert 324 == len(data)
    assert 'ffffffffffff4061' == data[:16]
