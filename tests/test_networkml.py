import os
import shutil
import sys
import tempfile
import pytest

from networkml.NetworkML import NetworkML


def copy_model(model, tempdir):
    src_test_dir = os.path.dirname(model)
    dst_test_dir = os.path.join(tempdir.name, os.path.basename(src_test_dir))
    test_model = os.path.join(dst_test_dir, os.path.basename(model))
    if not os.path.exists(dst_test_dir):
        shutil.copytree(src_test_dir, dst_test_dir)
    return test_model


def run_networkml(args, expected_code=0,
                  model='networkml/trained_models/onelayer/OneLayerModel.pkl',
                  sos_model='networkml/trained_models/sos/SoSmodel'):
    tempdir = tempfile.TemporaryDirectory()
    if model:
        test_model = copy_model(model, tempdir)
        args.extend(['-m', test_model])
    if sos_model:
        test_model = copy_model(sos_model, tempdir)
        args.extend(['-s', test_model])
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
    netml = run_networkml(
        ['-p', 'tests/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap', '-a', 'sos'])
    assert netml.model.feature_list


def test_networkml_train_onelayer():
    run_networkml(['-p', 'tests/', '-o', 'train'], expected_code=1)


def test_networkml_train_randomforest():
    run_networkml(
        ['-p', 'tests/', '-o', 'train', '-a', 'randomforest'],
        expected_code=1,
        model='networkml/trained_models/randomforest/RandomForestModel.pkl')


def test_networkml_train_sos():
    netml = run_networkml(
        ['-p', 'tests/', '-o', 'train', '-a', 'sos'],
        model='networkml/trained_models/sos/SoSmodel')
    assert not netml.model.feature_list


def test_networkml_test_onelayer():
    run_networkml(['-p', 'tests/', '-o', 'test'], expected_code=1)


def test_networkml_test_randomforest():
    os.environ['POSEIDON_PUBLIC_SESSIONS'] = ''
    netml = run_networkml(
        ['-p', 'tests/', '-o', 'test', '-a', 'randomforest'],
        model='networkml/trained_models/randomforest/RandomForestModel.pkl')
    assert netml.model.feature_list
