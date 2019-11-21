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
    assert parse_pcap_name('trace_ab12_2001-01-01_02_03-miscellaneous-stuff.pcap') == (
        None, None)


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
