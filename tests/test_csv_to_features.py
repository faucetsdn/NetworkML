import sys

from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_CSVToFeatures():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark', '-o', '/tmp/combined.csv.gz', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_dir():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', '/tmp/foo', './tests']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark', '/tmp/foo']
    instance2 = CSVToFeatures()
    instance2.main()

