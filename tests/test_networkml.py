import sys

from networkml.NetworkML import NetworkML


def test_networkml_eval_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/']
    netml = NetworkML()


def test_networkml_eval_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-a', 'randomforest']
    netml = NetworkML()


def test_networkml_eval_sos():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-a', 'sos']
    netml = NetworkML()


def test_networkml_eval_bad():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-a', 'bad']
    netml = NetworkML()


def test_networkml_train_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'train']
    netml = NetworkML()


def test_networkml_train_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/',
                '-o', 'train', '-a', 'randomforest']
    netml = NetworkML()


def test_networkml_train_sos():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'train', '-a', 'sos']
    netml = NetworkML()


def test_networkml_train_bad():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'train', '-a', 'bad']
    netml = NetworkML()


def test_networkml_test_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'test']
    netml = NetworkML()


def test_networkml_test_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/',
                '-o', 'test', '-a', 'randomforest']
    netml = NetworkML()


def test_networkml_test_sos():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'test', '-a', 'sos']
    netml = NetworkML()


def test_networkml_test_bad():
    sys.argv = ['bin/networkml', '-p',
                'tests/test.pcap', '-o', 'test', '-a', 'bad']
    netml = NetworkML()


def test_networkml_bad():
    sys.argv = ['bin/networkml', '-o', 'bad']
    netml = NetworkML()
