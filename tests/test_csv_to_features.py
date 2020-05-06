import os
import shutil
import sys
import tempfile

from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV

C2FARGS = ['csv_to_features.py', '-c', '-g', 'host_tshark']
P2CARGS = ['pcap_to_csv.py', '-e', 'tshark']


def test_CSVToFeatures():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        foo1 = os.path.join(tmpdir, 'foo-1.csv.gz')
        trace = os.path.join(
            testdata, 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap')
        sys.argv = P2CARGS + ['-o', foo1, trace]
        instance = PCAPToCSV()
        instance.main()
        sys.argv = C2FARGS + ['-o', os.path.join(tmpdir, 'combined.csv.gz'), foo1]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_no_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        foox = os.path.join(tmpdir, 'foo-x.csv.gz')
        trace = os.path.join(
            testdata, 'trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap')
        sys.argv = P2CARGS + ['-o', foox, trace]
        instance = PCAPToCSV()
        instance.main()
        sys.argv = C2FARGS + ['-o', os.path.join(tmpdir, 'combined.csv.gz'), foox]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_no_group_or_func():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        trace = os.path.join(
            testdata, 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz')
        sys.argv = ['csv_to_features.py', '-g', '', trace]
        instance = CSVToFeatures()
        instance.main()


def test_CSVToFeatures_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        foo2 = os.path.join(tmpdir, 'foo2')
        testsdir = os.path.join(tmpdir, 'tests')
        shutil.copytree('tests', testsdir)
        sys.argv = P2CARGS + ['-o', foo2, testsdir]
        instance = PCAPToCSV()
        instance.main()
        sys.argv = C2FARGS + ['-t', '2', foo2]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_dir_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        foo2 = os.path.join(tmpdir, 'foo2')
        foo2out = os.path.join(tmpdir, 'foo2_output')
        testsdir = os.path.join(tmpdir, 'tests')
        shutil.copytree('tests', testsdir)
        sys.argv = P2CARGS + ['-o', foo2, testsdir]
        instance = PCAPToCSV()
        instance.main()
        sys.argv = C2FARGS + ['-t', '2', '-o', foo2out, foo2]
        instance2 = CSVToFeatures()
        instance2.main()


def test_CSVToFeatures_host():
    for srcidflag in ('--srcmacid', '--no-srcmacid'):
        for featurizer in ('sessionhost_tshark', 'host_tshark'):
            with tempfile.TemporaryDirectory() as tmpdir:
                foo3 = os.path.join(tmpdir, 'foo3')
                testsdir = os.path.join(tmpdir, 'tests')
                shutil.copytree('tests', testsdir)
                sys.argv = P2CARGS + ['-o', foo3, testsdir]
                instance = PCAPToCSV()
                instance.main()
                sys.argv = ['csv_to_features.py', '-c', '-z', 'input', '-g', featurizer, foo3]
                instance2 = CSVToFeatures()
                instance2.main()
