import datetime
import networkml.parsers.pcap.reader


def test_packetizer():
    packet_dict, highest_layers = networkml.parsers.pcap.reader.packetizer(
        'tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap')
    assert {'BOOTP_RAW'} == highest_layers['172.16.0.1:67']
    assert {'HTTP_RAW', 'IMAGE-JFIF_RAW', 'TCP_RAW'} == highest_layers['192.168.3.131:56255']
    assert {'SSL_RAW', 'TCP_RAW'} == highest_layers['172.16.255.1:10659']
    assert {'ICMP_RAW'} == highest_layers['67.215.65.132:0']
    assert {'DNS_RAW'} == highest_layers['192.168.3.131:60629']
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


def test_sessionizer():
    pcap_file_sessions = networkml.parsers.pcap.reader.parallel_sessionizer(
        ['tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap'])
    binned_sessions = pcap_file_sessions.get(
        'tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap', None)
    assert binned_sessions is not None
    first_session = binned_sessions[0]
    packet_key = ('172.16.255.1:10670', '204.194.237.136:80')
    first_data = first_session[packet_key][0]
    timestamp, packet = first_data
    assert packet is not None
    assert isinstance(timestamp, datetime.datetime)
