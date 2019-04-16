from networkml.parsers.pcap.pcap_utils import extract_macs
from networkml.parsers.pcap.pcap_utils import extract_protocol
from networkml.parsers.pcap.pcap_utils import extract_session_size
from networkml.parsers.pcap.pcap_utils import is_external
from networkml.parsers.pcap.pcap_utils import is_private
from networkml.parsers.pcap.pcap_utils import is_protocol
from networkml.parsers.pcap.pcap_utils import packet_size


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


def test_packet_size():
    packet = ['0', '1234567890123456789012345678901234567890']
    size = packet_size(packet)
    assert size == 13398


def test_extract_session_size():
    session = [['0', '1234567890123456789012345678901234567890']]
    session_size = extract_session_size(session)
    assert session_size == 13398


def test_extract_protocol():
    session = [['0', '12345678901234567890123456789012345678901234567890']]
    protocol = extract_protocol(session)
    assert protocol == '78'


def test_is_external():
    external = is_external('10.10.10.10', '192.168.0.1')
    assert external == False
    external = is_external('10.10.10.10', '1.2.3.4')
    assert external == True


def test_is_protocol():
    session = [['0', '12345678901234567890123456789012345678901234567890']]
    protocol = is_protocol(session, '78')
    assert protocol == True
    protocol = is_protocol(session, 78)
    assert protocol == False
