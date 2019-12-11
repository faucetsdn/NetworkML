import os
import sys

import pytest

from networkml.NetworkML import NetworkML


def run_networkml(args, expected_code=0):
    sys.argv = ['bin/networkml'] + args
    if expected_code:
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            netml = NetworkML()
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == expected_code
        return netml
    else:
        return NetworkML()


def test_networkml_nofiles():
    netml = run_networkml([])
    assert netml.model.feature_list


def test_networkml_eval_onelayer():
    netml = run_networkml(['-p', 'tests/'])
    assert netml.model.feature_list


def test_networkml_eval_randomforest():
    os.environ['POSEIDON_PUBLIC_SESSIONS'] = ''
    netml = run_networkml(['-p', 'tests/', '-a', 'randomforest'])
    assert netml.model.feature_list


def test_networkml_eval_sos():
    netml = run_networkml([
        '-p', 'tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap',
        '-a', 'sos'])
    assert netml.model.feature_list


def test_networkml_train_onelayer():
    run_networkml(['-p', 'tests/', '-o', 'train'], expected_code=1)


def test_networkml_train_randomforest():
    run_networkml([
        '-p', 'tests/',
        '-o', 'train', '-a', 'randomforest',
        '-m', 'networkml/trained_models/randomforest/RandomForestModel.pkl'],
        expected_code=1)


def test_networkml_train_sos():
    netml = run_networkml([
        '-p', 'tests/', '-o', 'train',
        '-a', 'sos', '-m', 'networkml/trained_models/sos/SoSmodel'])
    assert not netml.model.feature_list


def test_networkml_test_onelayer():
    run_networkml(['-p', 'tests/', '-o', 'test'], expected_code=1)


def test_networkml_test_randomforest():
    os.environ['POSEIDON_PUBLIC_SESSIONS'] = ''
    netml = run_networkml([
        '-p', 'tests/',
        '-o', 'test', '-a', 'randomforest',
        '-m', 'networkml/trained_models/randomforest/RandomForestModel.pkl'])
    assert netml.model.feature_list
