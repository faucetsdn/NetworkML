import numpy as np

from utils.Model import Model


def test_augment_data():
    model = Model(10)
    a = [[1, 2, 3], [4, 5, 6]]
    x = np.array(a)
    a = ['label1', 'label2', 'Unknown']
    y = np.array(a)
    model._augment_data(x, y)
