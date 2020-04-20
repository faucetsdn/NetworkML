import os
import shutil
import sys
import tempfile

from networkml.parsers.pcap_to_csv import PCAPToCSV


def test_PCAPToCSV_pyshark_packet():
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        sys.argv = ['pcap_to_csv.py', '-c', '-e', 'pyshark', '-t', '2', '-v', 'DEBUG', '-o', os.path.join(
            tmpdir, 'networkml_test.pcap.csv.gz'), os.path.join(testdata, 'trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap')]
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
