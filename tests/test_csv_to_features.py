import sys
import tempfile
import os

from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_CSVToFeatures():
    with tempfile.TemporaryDirectory() as tmpdir:
        sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', os.path.join(tmpdir, 'foo-1.csv.gz'),
                    './tests/test_data/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap']
        instance = PCAPToCSV()
        instance.main()
        sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark',
                    '-o', os.path.join(tmpdir, 'combined.csv.gz'), os.path.join(tmpdir, 'foo-1.csv.gz')]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_no_output():
    sys.argv = ['pcap_to_csv.py', '-e', 'tshark', './tests/test_data/trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap']
    instance = PCAPToCSV()
    instance.main()
    sys.argv = ['csv_to_features.py', '-c', '-g', 'tshark', './tests/test_data/trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap.csv.gz']
    instance2 = CSVToFeatures()
    instance2.main()


def test_CSVToFeatures_no_group_or_func():
    sys.argv = ['csv_to_features.py', '-g', '', './tests/test_data/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz']
    instance = CSVToFeatures()
    instance.main()


def test_CSVToFeatures_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', os.path.join(tmpdir, 'foo2'), './tests']
        instance = PCAPToCSV()
        instance.main()
        sys.argv = ['csv_to_features.py', '-t', '2', '-c', '-g', 'tshark', os.path.join(tmpdir, 'foo2')]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_dir_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        foo2 = os.path.join(tmpdir, 'foo2')
        foo2out = os.path.join(tmpdir, 'foo2_output')
        sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', foo2, './tests']
        instance = PCAPToCSV()
        instance.main()
        sys.argv = ['csv_to_features.py', '-t', '2', '-c', '-g', 'tshark', '-o', foo2out, foo2]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_generic():
    with tempfile.TemporaryDirectory() as tmpdir:
        foo1 = os.path.join(tmpdir, 'foo1')
        sys.argv = ['pcap_to_csv.py', '-e', 'tshark', '-o', foo1, './tests']
        instance = PCAPToCSV()
        instance.main()
        sys.argv = ['csv_to_features.py', '-z', 'input', '-f', 'Generic:all', '-g', 'None', foo1]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_host():
    with tempfile.TemporaryDirectory() as tmpdir:
        foo3 = os.path.join(tmpdir, 'foo3')
        sys.argv = ['pcap_to_csv.py', '-e', 'pyshark', '-o', foo3, './tests']
        instance = PCAPToCSV()
        instance.main()
        sys.argv = ['csv_to_features.py', '-c', '-z', 'input', '-g', 'pyshark', foo3]
        instance2 = CSVToFeatures()
        instance2.main()
