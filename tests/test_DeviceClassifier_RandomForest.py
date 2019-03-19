import logging
import os
import sys

from DeviceClassifier.RandomForest import train_RandomForest
from DeviceClassifier.RandomForest.eval_RandomForest import RandomForestEval


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_randomforesteval():
    os.environ['RABBIT'] = 'False'
    instance = RandomForestEval()
    # instance.main()

    last_update = instance.common.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.common.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None


def test_randomforesteval_main():
    os.environ['RABBIT'] = 'False'
    instance = RandomForestEval()

    sys.argv = ['foo', '.']
    instance.main()
    sys.argv = ['foo', 'AUTHORS']
    instance.main()
    sys.argv = ['foo', os.path.join(os.getcwd(), 'tests/test.pcap'), os.path.join(
        os.getcwd(), 'DeviceClassifier/RandomForest/models/RandomForestModel.pkl')]
    instance.main()
