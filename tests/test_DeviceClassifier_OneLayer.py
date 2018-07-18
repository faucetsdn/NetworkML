from DeviceClassifier.OneLayer.test_OneLayer import calc_f1
from DeviceClassifier.OneLayer.eval_OneLayer import lookup_key
from DeviceClassifier.OneLayer.eval_OneLayer import get_address_info
from DeviceClassifier.OneLayer.eval_OneLayer import get_previous_state
from DeviceClassifier.OneLayer.eval_OneLayer import average_representation
from DeviceClassifier.OneLayer.eval_OneLayer import update_data
from DeviceClassifier.OneLayer.eval_OneLayer import basic_decision

def test_calc_f1():
    calc_f1({})
