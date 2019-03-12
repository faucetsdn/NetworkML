import os
from shutil import copyfile

import numpy as np

from utils.Model import Model


def test_augment_data():
    model = Model(10, labels=['Unknown'])
    a = [[1, 2, 3], [4, 5, 6]]
    x = np.array(a)
    a = ['label1', 'label2', 'label3']
    y = np.array(a)
    model._augment_data(x, y)


def test_get_features():
    model = Model(10, labels=['Unknown'])
    with open('tests/test.pcap', 'a'):
        os.utime('tests/test.pcap', None)
    if not os.path.isfile('opts/config.json'):
        os.makedirs('opts')
        copyfile('DeviceClassifier/OneLayer/opts/config.json',
                 'opts/config.json')
    model.get_features('tests/test.pcap')
