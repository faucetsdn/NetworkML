from networkml.featurizers.funcs.packet import Packet


def test_packet_all():
    instance = Packet()
    result = instance.all('foo')
    assert result == 'foo'
