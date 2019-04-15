import sys

from networkml.networkml import NetworkML


def test_networkml():
    sys.argv = ['bin/networkml', '-p', 'tests/']
    netml = NetworkML()
