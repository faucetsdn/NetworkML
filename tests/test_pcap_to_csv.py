import sys

from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_PCAPToCSV():
    sys.argv = ['pcap_to_csv.py', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()
