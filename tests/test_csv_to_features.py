import sys

from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_CSVToFeatures():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', '/tmp/foo-1.csv.gz', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark', '-o', '/tmp/combined.csv.gz', '/tmp/foo-1.csv.gz']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_no_output():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', './tests/trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark', './tests/trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap.csv.gz']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_no_group_or_func():
    sys.argv = ['csv_to_features.py', '-g', '', './tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz']
    instance = CSVToFeatures()
    instance.main()


def test_CSVToFeatures_dir():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', '/tmp/foo2', './tests']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-t', '2', '-c', '-g', 'tshark', '/tmp/foo2']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_dir_output():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', '/tmp/foo2', './tests']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-t', '2', '-c', '-g', 'tshark', '-o', '/tmp/foo2_output', '/tmp/foo2']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_generic():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', '/tmp/foo1', './tests']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-z', 'input', '-f', 'Generic:all', '/tmp/foo1']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_host():
    sys.argv = ['pcap_to_csv.py', '-e', 'pyshark', '-o', '/tmp/foo3', './tests']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-z', 'input', '-g', 'pyshark', '/tmp/foo3']
    instance2 = CSVToFeatures()
    instance2.main()
