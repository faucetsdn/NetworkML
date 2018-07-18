from DeviceClassifier.RandomForest.test_RandomForest import calc_f1
from DeviceClassifier.RandomForest.eval_RandomForest import lookup_key
from DeviceClassifier.RandomForest.eval_RandomForest import get_address_info
from DeviceClassifier.RandomForest.eval_RandomForest import get_previous_state
from DeviceClassifier.RandomForest.eval_RandomForest import average_representation
from DeviceClassifier.RandomForest.eval_RandomForest import update_data
from DeviceClassifier.RandomForest.eval_RandomForest import basic_decision

def test_calc_f1():
    calc_f1({})
