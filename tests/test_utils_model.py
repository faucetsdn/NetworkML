import os
from shutil import copyfile

import numpy as np

from networkml.utils.model import Model


def test_augment_data():
    model = Model(10, labels=['Unknown'])
    a = [[1, 2, 3], [4, 5, 6]]
    x = np.array(a)
    a = ['label1', 'label2', 'label3']
    y = np.array(a)
    model._augment_data(x, y)
