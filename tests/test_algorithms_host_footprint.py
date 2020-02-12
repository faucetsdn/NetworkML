from networkml.algorithms.host_footprint import HostFootprint


def test_train():
    input_file = './tests/combined.csv'
    HostFootprint(input_file, 'train')


def test_predict():
    input_file = './tests/combined.csv'
    HostFootprint(input_file, 'predict')
