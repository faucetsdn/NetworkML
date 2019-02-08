import logging
import os

from DeviceClassifier.OneLayer import train_OneLayer
from DeviceClassifier.OneLayer.eval_OneLayer import OneLayerEval


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_onelayereval():
    os.environ['SKIP_RABBIT'] = 'True'
    instance = OneLayerEval()
    # instance.main()

    last_update = instance.common.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.common.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None
