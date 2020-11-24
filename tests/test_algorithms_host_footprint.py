import json
import os
import shutil
import sys
import tempfile

import numpy as np
import pytest
from sklearn import preprocessing
from sklearn.preprocessing import StandardScaler

from networkml.algorithms.host_footprint import HostFootprint


def test_serialize_scaler():
    instance = HostFootprint()
    scaler = StandardScaler()
    test_data = [[i, i] for i in range(99)]
    scaler.fit(test_data)
    with tempfile.TemporaryDirectory() as tmpdir:
        scaler_file = os.path.join(tmpdir, 'scaler.mod')
        instance.serialize_scaler(scaler, scaler_file)
        new_scaler = instance.deserialize_scaler(scaler_file)
        assert len(scaler.mean_) == 2
        assert scaler.mean_.tolist() == new_scaler.mean_.tolist()


def test_serialize_label_encoder():
    instance = HostFootprint()
    le_classes = ['printer', 'workstation', 'server']
    le = preprocessing.LabelEncoder()
    le.fit(le_classes)
    with tempfile.TemporaryDirectory() as tmpdir:
        le_file = os.path.join(tmpdir, 'le.json')
        instance.serialize_label_encoder(le, le_file)
        new_le = instance.deserialize_label_encoder(le_file)
        assert le.classes_.tolist() == new_le.classes_.tolist()
        assert new_le.inverse_transform(le.transform(le_classes)).tolist() == le_classes


def test_get_individual_predictions():
   le_classes = ['asomething', 'bsomething']
   le = preprocessing.LabelEncoder()
   le.fit(le_classes)
   filename = ['firstfile']
   host_key = np.array(['mac1'])
   tshark_srcips = np.array(["['1.1.1.1']"])
   frame_epoch = None
   instance = HostFootprint()
   assert instance.get_individual_predictions([[0.6, 0.7]], le, filename, host_key, tshark_srcips, frame_epoch) == {
        'firstfile': [{'top_role': 'bsomething', 'role_list': [('bsomething', 0.7), ('asomething', 0.6)], 'source_ip': '1.1.1.1', 'source_mac': 'mac1'}]}
   assert instance.get_individual_predictions([[0.2, 0.1]], le, filename, host_key, tshark_srcips, frame_epoch) == {
        'firstfile': [{'top_role': 'Unknown', 'role_list': [('asomething', 0.2), ('bsomething', 0.1)], 'source_ip': '1.1.1.1', 'source_mac': 'mac1'}]}


def hf_args(tmpdir, operation, input_file):
    output_json = os.path.join(tmpdir, 'out.json')
    output_le_json = os.path.join(tmpdir, 'out_le.json')
    scaler_mod = os.path.join(tmpdir, 'scaler.mod')
    return ['host_footprint.py', '--label_encoder', output_le_json,
            '--trained_model', output_json, '--scaler', scaler_mod,
            '--operation', operation, '--kfolds', '2', input_file]


def test_train():
    """Test training function of HostFootprint class"""
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        input_file = os.path.join(testdata, 'combined.csv')
        operation = 'train'
        sys.argv = hf_args(tmpdir, operation, input_file)
        instance = HostFootprint()
        instance.main()


def test_predict():
    """Test predict function of HostFootprint class"""
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        input_file = os.path.join(testdata, 'combined.csv')
        operation = 'train'
        sys.argv = hf_args(tmpdir, operation, input_file)
        instance = HostFootprint()
        instance.main()
        operation = 'predict'
        sys.argv = hf_args(tmpdir, operation, input_file)
        instance = HostFootprint()
        json.loads(instance.main())


def test_predict_num_roles():
    """
    Test predict function of HostFootprint class with
    varying number of distinct roles present
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        for file in ['combined_three_roles.csv', 'combined_two_roles.csv']:
            input_file = os.path.join(testdata, file)
            operation = 'train'
            sys.argv = hf_args(tmpdir, operation, input_file)
            instance = HostFootprint()
            instance.main()
            operation = 'predict'
            sys.argv = hf_args(tmpdir, operation, input_file)
            instance = HostFootprint()
            instance.main()

            predictions = json.loads(instance.predict())
            assert isinstance(predictions, dict)
            # Check if number of predictions is correct
            if file == 'combined_three_roles.csv':
                assert len(predictions) == 6
            else:
                assert len(predictions) == 4


def test_train_bad_data_too_few_columns():
    """
    This test tries to train a model on a mal-formed csv with too few fields
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        testdata = os.path.join(tmpdir, 'test_data')
        shutil.copytree('./tests/test_data', testdata)
        input_file = os.path.join(testdata, 'bad_data_too_few_columns.csv')
        operation = 'train'
        sys.argv = hf_args(tmpdir, operation, input_file)
        instance = HostFootprint()
        with pytest.raises(Exception):
            instance.main()
