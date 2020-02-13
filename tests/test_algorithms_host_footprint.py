import sys

from networkml.algorithms.host_footprint import HostFootprint


def test_train():
    input_file = './tests/combined.csv'
    operation = 'train'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    HostFootprint()


def test_predict():
    input_file = './tests/combined.csv'
    operation = 'predict'
    sys.argv = ['host_footprint.py', '--operation', operation, input_file]
    HostFootprint()
