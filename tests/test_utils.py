from utils import train_SoSModel
from utils.eval_SoSModel import eval_pcap
from utils.featurizer import extract_features
from utils.iterator import BatchIterator
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
from utils.reader import parse_packet_head
from utils.reader import parse_packet_data
from utils.reader import packetizer
from utils.reader import sessionizer
from utils.rnnclassifier import scope_decorator
from utils.rnnclassifier import get_available_gpus
from utils.rnnclassifier import weight_variable
from utils.rnnclassifier import bias_variable
from utils.rnnclassifier import AbnormalDetector
from utils.session_iterator import BatchIterator as SessBatchIterator
from utils.training_utils import read_data
from utils.training_utils import select_features
from utils.training_utils import whiten_features
from utils.training_utils import choose_regularization
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

def test_BatchIterator():
    instance = BatchIterator({}, {})

def test_SessBatchIterator():
    instance = SessBatchIterator({}, {})

def test_AbnormalDetector():
    instnace = AbnormalDetector()
