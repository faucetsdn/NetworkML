from DeviceClassifier.OneLayer import train_OneLayer
from DeviceClassifier.OneLayer.eval_OneLayer import lookup_key
from DeviceClassifier.OneLayer.eval_OneLayer import get_address_info
from DeviceClassifier.OneLayer.eval_OneLayer import get_previous_state
from DeviceClassifier.OneLayer.eval_OneLayer import average_representation
from DeviceClassifier.OneLayer.eval_OneLayer import update_data
from DeviceClassifier.OneLayer.eval_OneLayer import basic_decision
from DeviceClassifier.OneLayer.test_OneLayer import calc_f1

def test_calc_f1():
    calc_f1({})

def test_lookup_key():
    address, e = lookup_key('foo')
    assert address == None

def test_get_address_info():
    current_state, average_state, other_ips, last_update, labels, conf = get_address_info('10.0.0.1', '1', 1)

def test_get_previous_state():
    last_update, previous_representation = get_previous_state('10.0.0.1', '1')
    assert last_update == None
    assert previous_representation == None
