import logging

from networkml.algorithms.randomforest.RandomForest import RandomForest


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_randomforest():
    instance = RandomForest()

    last_update = instance.common.get_address_info('10.0.0.1', '1')
    last_update, previous_representation = instance.common.get_previous_state(
        '10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None


def test_randomforest_eval():
    instance = RandomForest()
    instance.eval()
