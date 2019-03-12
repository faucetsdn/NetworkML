from utils.pcap_utils import extract_macs


def test_extract_macs():
    source, dest = extract_macs('123456789ABCDEF123456780')
    assert dest == '12:34:56:78:9A:BC'
    assert source == 'DE:F1:23:45:67:80'
