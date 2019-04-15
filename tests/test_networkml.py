import sys

import pytest

from networkml.NetworkML import NetworkML


def test_networml_nofiles():
    sys.argv = ['bin/networkml']
    netml = NetworkML()


def test_networkml_eval_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/']
    netml = NetworkML()


def test_networkml_eval_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-a', 'randomforest']
    netml = NetworkML()


def test_networkml_eval_sos():
    sys.argv = ['bin/networkml', '-p', 'tests/test.pcap', '-a', 'sos']
    netml = NetworkML()


def test_networkml_train_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'train']
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        netml = NetworkML()
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


def test_networkml_train_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/',
                '-o', 'train', '-a', 'randomforest', '-m', 'networkml/trained_models/randomforest/RandomForestModel.pkl']
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        netml = NetworkML()
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


def test_networkml_train_sos():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'train',
                '-a', 'sos', '-m', 'networkml/trained_models/sos/SoSmodel']
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        netml = NetworkML()
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


def test_networkml_test_onelayer():
    sys.argv = ['bin/networkml', '-p', 'tests/', '-o', 'test']
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        netml = NetworkML()
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


def test_networkml_test_randomforest():
    sys.argv = ['bin/networkml', '-p', 'tests/',
                '-o', 'test', '-a', 'randomforest', '-m', 'networkml/trained_models/randomforest/RandomForestModel.pkl']
    netml = NetworkML()
