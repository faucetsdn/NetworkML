import os
import shutil
import sys
import tempfile
import pytest

from networkml.algorithms.host_footprint import HostFootprint


def hf_args(tmpdir, operation, input_file):
    output_json = os.path.join(tmpdir, 'out.json')
    output_le_json = os.path.join(tmpdir, 'out_le.json')
    return ['host_footprint.py', '-l', output_le_json, '-t', output_json,
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
        instance.main()


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
