from utils.featurizer import extract_features
from utils.pcap_utils import is_private
from utils.pcap_utils import extract_macs
from utils.pcap_utils import get_indiv_source
from utils.pcap_utils import get_source
from utils.pcap_utils import packet_size
from utils.pcap_utils import extract_session_size
from utils.pcap_utils import extract_protocol
from utils.pcap_utils import is_external
from utils.pcap_utils import is_protocol
from utils.pcap_utils import strip_macs
from utils.pcap_utils import strip_ips
from utils.pcap_utils import clean_packet
from utils.pcap_utils import clean_session_dict
from utils.pcap_utils import create_inputs
from utils.pcap_utils import get_length
from utils.pcap_utils import featurize_session
from utils.pcap_utils import get_ip_port

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
