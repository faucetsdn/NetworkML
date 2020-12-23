import json
import logging
import time
import os

from networkml.helpers.results_output import ResultsOutput


def test_parse_pcap_name():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'uid', '/path')
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

def test_output_from_result_json():
    logger = logging.getLogger(__name__)
    instance = ResultsOutput(logger, 'testver', 'path/')
    result_json = {
        '/dir/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap': [{
            'top_role': 'foo',
            'source_ip': '1.2.3.4',
            'source_mac': '01:02:03:04:05:06',
            'timestamp': 999,
            'role_list': [('bsomething', 0.7), ('asomething', 0.6), ('csomething', 0.5)]}],
    }
    reformatted_result_json_file = os.devnull
    reformatted_json = instance.output_from_result_json(json.dumps(result_json), reformatted_result_json_file)
    assert reformatted_json == {'tool': 'networkml', 'data': {'mac_addresses': {'01:02:03:04:05:06': {'uid': 'testver', 'file_path': 'path/', 'pcap': '', 'pcap_key': '', 'pcap_labels': None, 'timestamp': 999, 'source_ip': '1.2.3.4', 'decisions': {'investigate': False}, 'classification': {'labels': ['bsomething', 'asomething', 'csomething'], 'confidences': (0.7, 0.6, 0.5)}}}}}  # nosec - fine in a test.
