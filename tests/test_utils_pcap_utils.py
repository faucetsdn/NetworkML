from networkml.parsers.pcap.pcap_utils import extract_macs
from networkml.parsers.pcap.pcap_utils import is_private


def test_extract_macs():
    source, dest = extract_macs('123456789ABCDEF123456780')
    assert dest == '12:34:56:78:9A:BC'
    assert source == 'DE:F1:23:45:67:80'


def test_is_private():
    private = is_private('10.10.10.10')
    assert private == True
    private = is_private('1.2.3.4')
    assert private == False
    private = is_private('192.168.1.1')
    assert private == True
    private = is_private('192.169.1.1')
    assert private == False
    private = is_private('172.16.4.4')
    assert private == True
    private = is_private('172.15.1.3')
    assert private == False
    private = is_private('172.32.3.1')
    assert private == False
    private = is_private('2014::1')
    assert private == False
    private = is_private('fe80::1')
    assert private == True
    private = is_private('fd13::13')
    assert private == True
    private = is_private('asdf')
    assert private == False
