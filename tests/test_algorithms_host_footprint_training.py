from networkml.algorithms.host_footprint_training import train


def test_train():
    input_file = './tests/combined.csv'
    train(input_file)
