import datetime
import logging
import tempfile
import os
import sys
import networkml.parsers.pcap.reader
from networkml.parsers.pcap.pcap_utils import extract_macs, packet_size


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
    # We have to drop date from comparison because reader.py doesn't use UTC consistently.
    # Migrate to UTC in the future.
    head, data = packet_list[0]
    assert ('40:61:86:9a:f1:f5', '00:1a:8c:15:f9:80') == extract_macs(data)
    assert 983 == packet_size([0, data])
    assert 108 == len(data)
    assert '001a8c15f9804061' == data[:16]
    _, key1, key2 = head
    assert ('192.168.3.131:57011', '72.14.213.138:80') == (key1, key2)
    head, data = packet_list[-1]
    assert ('40:61:86:9a:f1:f5', 'ff:ff:ff:ff:ff:ff') == extract_macs(data)
    assert 148 == packet_size([0, data])
    assert 68 == len(data)
    assert 'ffffffffffff4061' == data[:16]
    _, key1, key2 = head
    assert ('192.168.3.131:17500', '192.168.3.255:17500') == (key1, key2)


def test_sessionizer():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('test')
    pcap_file = 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap'
    with tempfile.TemporaryDirectory() as tempdir:
        pcap_path = os.path.join('tests', pcap_file)
        pcap_file_sessions = networkml.parsers.pcap.reader.parallel_sessionizer(
            logger, [pcap_path], csv_out_dir=tempdir)
        binned_sessions = pcap_file_sessions.get(pcap_path, None)
        # smoke test - can read session from pcap
        assert binned_sessions is not None
        first_session = binned_sessions[0]
        packet_key = ('172.16.255.1:10670', '204.194.237.136:80')
        first_data = first_session[packet_key][0]
        timestamp, packet = first_data
        assert packet is not None
        assert isinstance(timestamp, datetime.datetime)
        # read CSV version of sessions back in.
        csv_file = networkml.parsers.pcap.reader.pcap_filename_to_csv_filename(pcap_file, tempdir)
        binned_sessions_from_csv = networkml.parsers.pcap.reader.sessioncsv_to_sessions(csv_file)
        first_session_from_csv = binned_sessions_from_csv[0]
        # CSV version should be the same as read from pcap.
        assert len(first_session) == len(first_session_from_csv)
        for pcap_items, csv_items in zip(first_session.items(), first_session_from_csv.items()):
            assert pcap_items == csv_items
