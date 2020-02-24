import sys
import pytest

from networkml.algorithms.host_footprint import HostFootprint


def test_train():
    """Test training function of HostFootprint class"""
    input_file = './tests/test_data/combined.csv'
    operation = 'train'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    HostFootprint()


def test_predict():
    """Test predict function of HostFootprint class"""
    input_file = './tests/test_data/combined.csv'
    operation = 'train'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    HostFootprint()
    operation = 'predict'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    HostFootprint()


def test_train_bad_data_too_few_columns():
    """
    This test tries to train a model on a mal-formed csv with too few fields
    """
    input_file = './tests/test_data/bad_data_too_few_columns.csv'
    operation = 'train'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    with pytest.raises(Exception):
        HostFootprint()
