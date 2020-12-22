import json
import logging
import time

from networkml.helpers.results_output import ResultsOutput


def test_parse_pcap_name():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    assert instance.parse_pcap_name('notaposeidontracefile.pcap') == (
        'notaposeidontracefile', None)
    assert instance.parse_pcap_name('trace_but_invalid') == (
        None, None)
    assert instance.parse_pcap_name('trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap') == (
        'ab12', 'ip-1-2-3-4')
    assert instance.parse_pcap_name('trace_8adfcc152604e75d37a1a2ac62124ae859105239_2020-01-21_21_31_44-client-ip-17-253-66-125-17-253-66-125-192-168-3-2-udp-frame-ntp-wsshort-ip-eth-port-123.pcap') == (
        '8adfcc152604e75d37a1a2ac62124ae859105239', 'ip-17-253-66-125-17-253-66-125-192-168-3-2-udp-frame-ntp-wsshort-ip-eth-port-123')
    assert instance.parse_pcap_name('trace_8198b3326dcb032a2bfbb8030339ff2159b9993d_2020-02-19_03_16_21.pcap') == (
        '8198b3326dcb032a2bfbb8030339ff2159b9993d', None)
    assert instance.parse_pcap_name('trace_ab12_2001-01-01_02_03-miscellaneous-stuff.pcap') == (
        None, None)


def test_rabbit_msg_template():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    assert instance.rabbit_msg_template('x', 'y', 'z') == {
        'id': 'x', 'type': 'metadata', 'file_path': 'y', 'data': 'z', 'results': {'tool': 'networkml', 'version': 'testver'}}


def test_results_template():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    assert instance.results_template(
        '/some/dir/trace_ab34_2001-01-01_02_03-client-ip-1-2-3-4.pcap', False, {}) == {'ab34': {'pcap_labels': 'ip-1-2-3-4', 'valid': False}, 'pcap': 'trace_ab34_2001-01-01_02_03-client-ip-1-2-3-4.pcap'}
    assert instance.valid_template(
        99.0, '192.168.1.1', '0e:00:00:00:00:01', False, ['arole'], ['1.0']) == {'decisions': {'investigate': False}, 'classification': {'labels': ['arole'], 'confidences': ['1.0']}, 'timestamp': 99.0, 'source_ip': '192.168.1.1', 'source_mac': '0e:00:00:00:00:01'}


def test_rabbit_smoke_bad():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    for badhost, badport in (
            ('nosuchthing', 9999),
            ('127.0.0.1', 65537)):
        instance = ResultsOutput(logger, 'testver', True)
        instance.rabbit_host = badhost
        instance.rabbit_port = badport
        instance.output_msg('x', 'y', 'z')


def test_rabbit_smoke_good():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    instance.rabbit_host = '127.0.0.1'
    instance.output_msg('x', 'y', 'z')
    instance.output_invalid('1', '/some/file.pcap', 'file.pcap')
    instance.output_valid('1', '/some/file.pcap', 'file.pcap', 99.0, '1.2.3.4', '0e:00:00:00:00:01', ['arole'], ['1.0'])


def test_results_output():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', True)
    instance.rabbit_host = '127.0.0.1'
    results_json = json.dumps({
        'filename1': [{'top_role': 'role1', 'role_list': [['role1', 0.9], ['role2', 0.8], ['role3', 0.7]]}],
        'filename2': [{'top_role': 'Unknown', 'role_list': [['role1', 0.2], ['role2', 0.1], ['role3', 0.01]]}]})
    instance.output_from_result_json('1', '/some/file.pcap', results_json)
