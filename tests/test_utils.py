from utils.OneLayer import OneLayerModel
from utils.RandomForestModel import RandomForestModel
from utils.SoSmodel import scope_decorator
from utils.SoSmodel import get_available_gpus
from utils.SoSmodel import weight_variable
from utils.SoSmodel import bias_variable
from utils.SoSmodel import SoSModel

def test_OneLayerModel():
    instance = OneLayerModel(15)

def test_RandomForestModel():
    instance = RandomForestModel(15)

def test_SoSModel():
    instance = SoSModel()
