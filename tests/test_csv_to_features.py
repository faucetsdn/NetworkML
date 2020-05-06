import os
import shutil
import sys
import tempfile

from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV

COMMON_ARGS = ['-t', '2', '-v', 'DEBUG']


def run_pcap_to_csv(in_path, out_path, engine='tshark'):
    sys.argv = ['pcap_to_csv.py'] + COMMON_ARGS + ['-e', engine, '-o', out_path, in_path]
    instance = PCAPToCSV()
    instance.main()


def run_csv_to_features(in_path, out_path=None, featurizer='host_tshark', otherflag=None):
    args = ['csv_to_features.py'] + COMMON_ARGS + ['-g', featurizer]
    if otherflag:
        args.append(otherflag)
    if out_path:
        args.extend(['-o', out_path])
    args.append(in_path)
    sys.argv = args
    instance = CSVToFeatures()
    instance.main()


def run_pcap_to_features(pcap=None, outdir=False):
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        if pcap:
            pcap_path = os.path.join(testdata, pcap)
            pcap_csv_path = os.path.join(tmpdir, pcap + '.csv.gz')
        else:
            testsdir = os.path.join(tmpdir, 'tests')
            shutil.copytree('tests', testsdir)
            pcap_path = testsdir
            pcap_csv_path = os.path.join(tmpdir, 'pcap.csv.gz')
        run_pcap_to_csv(pcap_path, pcap_csv_path)
        if outdir:
            outpath = tmpdir
        else:
            outpath = os.path.join(tmpdir, 'combined.csv.gz')
        run_csv_to_features(pcap_csv_path, outpath)


def test_CSVToFeatures():
    run_pcap_to_features(pcap='trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap', outdir=False)


def test_CSVToFeatures_no_output():
    run_pcap_to_features(pcap='trace_ab12_2001-01-01_02_03-client-ip6-1-2-3-4.pcap', outdir=False)


def test_CSVToFeatures_input_dir_output_file():
    run_pcap_to_features(pcap=None, outdir=False)


def test_CSVToFeatures_input_dir_output_dir():
    run_pcap_to_features(pcap=None, outdir=True)


def test_CSVToFeatures_no_group_or_func():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        trace = os.path.join(testdata, 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz')
        run_csv_to_features(trace, featurizer='')


def test_CSVToFeatures_host():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        trace = os.path.join(testdata, 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap.csv.gz')
        for srcidflag in ('--srcmacid', '--no-srcmacid'):
            for featurizer in ('sessionhost_tshark', 'host_tshark'):
                run_csv_to_features(trace, featurizer=featurizer, otherflag=srcidflag)
