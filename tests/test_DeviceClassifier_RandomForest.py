import logging
import os

from DeviceClassifier.RandomForest import train_RandomForest
from DeviceClassifier.RandomForest.eval_RandomForest import RandomForestEval
from DeviceClassifier.RandomForest.test_RandomForest import calc_f1


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_calc_f1():
    calc_f1({}, logger)


def test_randomforesteval():
    os.environ['SKIP_RABBIT'] = 'True'
    instance = RandomForestEval()
    # instance.main()

    address, e = instance.common.lookup_key('foo')
    assert address == None

    last_update = instance.common.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.common.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None
