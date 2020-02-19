import logging

from networkml.algorithms.base import BaseAlgorithm


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_parse_pcap_name():
    instance = BaseAlgorithm()
    parse_pcap_name = instance.parse_pcap_name
    assert parse_pcap_name('notaposeidontracefile.pcap') == (
        'notaposeidontracefile', None)
    assert parse_pcap_name('trace_but_invalid') == (
        None, None)
    assert parse_pcap_name('trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap') == (
        'ab12', 'ip-1-2-3-4')
    assert parse_pcap_name('trace_8adfcc152604e75d37a1a2ac62124ae859105239_2020-01-21_21_31_44-client-ip-17-253-66-125-17-253-66-125-192-168-3-2-udp-frame-ntp-wsshort-ip-eth-port-123.pcap') == (
        '8adfcc152604e75d37a1a2ac62124ae859105239', 'ip-17-253-66-125-17-253-66-125-192-168-3-2-udp-frame-ntp-wsshort-ip-eth-port-123')
    assert parse_pcap_name('trace_8198b3326dcb032a2bfbb8030339ff2159b9993d_2020-02-19_03_16_21.pcap') == (
        '8198b3326dcb032a2bfbb8030339ff2159b9993d', None)
    assert parse_pcap_name('trace_ab12_2001-01-01_02_03-miscellaneous-stuff.pcap') == (
        None, None)


def test_parse_pcap_labels():
    instance = BaseAlgorithm()
    for label_str, result in (
         ('ip-8-8-8-8-192-168-254-254-8-8-8-8-ssl-ip-frame-wsshort-eth-tcp-port-443',
             {'ip_lowest_port': '443', 'ip_proto': 'tcp', 'ip_version': 4, 'ip_app': 'ssl'}),
         ('ip-17-253-110-125-17-253-110-125-192-168-3-2-wsshort-udp-ip-ntp-frame-eth-port-123',
             {'ip_lowest_port': '123', 'ip_proto': 'udp', 'ip_version': 4, 'ip_app': 'ntp'})):
        assert instance.parse_pcap_labels(label_str) == result

def test_has_avx():
    instance = BaseAlgorithm()
    assert isinstance(instance.has_avx(), bool)


def test_basealgorithm():
    instance = BaseAlgorithm()

    last_update = instance.common.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.common.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None


def test_basealgorithm_eval():
    instance = BaseAlgorithm()
    instance.eval('onelayer')
    instance.eval('randomforest')
