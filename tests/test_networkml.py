import sys

from networkml.NetworkML import NetworkML


def test_networkml():
    sys.argv = ['bin/networkml', '-p', 'tests/']
    netml = NetworkML()
