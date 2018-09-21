import logging
import os

from DeviceClassifier.OneLayer import train_OneLayer
from DeviceClassifier.OneLayer.eval_OneLayer import OneLayerEval
from DeviceClassifier.OneLayer.test_OneLayer import calc_f1


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_calc_f1():
    calc_f1({}, logger)


def test_onelayereval():
    os.environ['SKIP_RABBIT'] = 'True'
    instance = OneLayerEval()
    #instance.main()

    address, e = instance.lookup_key('foo')
    assert address == None

    last_update = instance.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None
