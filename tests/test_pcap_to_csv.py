import sys

from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_PCAPToCSV_pyshark_packet():
    sys.argv = ['pcap_to_csv.py', '-c', '-e', 'pyshark', '-t', '2', '-v', 'DEBUG', '-o', '/tmp/networkml_test.pcap.csv.gz', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()


def test_PCAPToCSV_tshark_flow():
    sys.argv = ['pcap_to_csv.py', '-c', '-e', 'tshark', '-l', 'flow', '-t', '2', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()


def test_ispcap():
    a = 'foo.bad'
    answer = PCAPToCSV.ispcap(a)
    assert answer == False
    a = 'fooo.pcap'
    answer = PCAPToCSV.ispcap(a)
    assert answer == True
    a = 'fooo.pcapng'
    answer = PCAPToCSV.ispcap(a)
    assert answer == True
    a = 'fooo.dump'
    answer = PCAPToCSV.ispcap(a)
    assert answer == True
    a = 'fooo.capture'
    answer = PCAPToCSV.ispcap(a)
    assert answer == True
