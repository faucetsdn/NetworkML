from scapy.layers.inet import IP
from networkml.parsers.pcap.pcap_utils import extract_macs
from networkml.parsers.pcap.pcap_utils import extract_protocol
from networkml.parsers.pcap.pcap_utils import extract_session_size
from networkml.parsers.pcap.pcap_utils import is_external
from networkml.parsers.pcap.pcap_utils import is_private
from networkml.parsers.pcap.pcap_utils import is_protocol
from networkml.parsers.pcap.pcap_utils import packet_size
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


TEST_IP_DATA = bytes(Ether()/IP(len=99,proto=6)/TCP()).hex()


def test_extract_macs():
    test_payload = '00' * 20
    macs = extract_macs('123456789ABCDEF123456780' + test_payload)
    assert macs is not None
    source, dest = macs
    assert dest == '12:34:56:78:9a:bc'
    assert source == 'de:f1:23:45:67:80'
    macs = extract_macs('020406080A0C0E0103050700' + test_payload)
    assert macs is not None
    source, dest = macs
    assert dest == '02:04:06:08:0a:0c'
    assert source == '0e:01:03:05:07:00'
    assert None == extract_macs('0000')
    assert None == extract_macs('01005e0000fc0050')


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
    packet = ['0', TEST_IP_DATA]
    size = packet_size(packet)
    assert size == 99


def test_extract_session_size():
    session = [['0', TEST_IP_DATA]]
    session_size = extract_session_size(session)
    assert session_size == 99


def test_extract_protocol():
    session = [['0', TEST_IP_DATA]]
    protocol = extract_protocol(session)
    assert protocol == '06'


def test_is_external():
    external = is_external('10.10.10.10', '192.168.0.1')
    assert external == False
    external = is_external('10.10.10.10', '1.2.3.4')
    assert external == True


def test_is_protocol():
    session = [['0', TEST_IP_DATA]]
    protocol = is_protocol(session, '06')
    assert protocol == True
    protocol = is_protocol(session, 6)
    assert protocol == False
