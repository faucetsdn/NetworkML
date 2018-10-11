import os
from utils import train_SoSModel
from utils.eval_SoSModel import eval_pcap
from utils.featurizer import extract_features
from utils.iterator import BatchIterator
from utils.Model import Model
from utils.pcap_utils import clean_packet
from utils.pcap_utils import clean_session_dict
from utils.pcap_utils import create_inputs
from utils.pcap_utils import extract_macs
from utils.pcap_utils import extract_protocol
from utils.pcap_utils import extract_session_size
from utils.pcap_utils import featurize_session
from utils.pcap_utils import get_indiv_source
from utils.pcap_utils import get_ip_port
from utils.pcap_utils import get_length
from utils.pcap_utils import get_source
from utils.pcap_utils import is_external
from utils.pcap_utils import is_private
from utils.pcap_utils import is_protocol
from utils.pcap_utils import packet_size
from utils.pcap_utils import strip_ips
from utils.pcap_utils import strip_macs
from utils.reader import packetizer
from utils.reader import parse_packet_data
from utils.reader import parse_packet_head
from utils.reader import sessionizer
from utils.rnnclassifier import AbnormalDetector
from utils.rnnclassifier import bias_variable
from utils.rnnclassifier import get_available_gpus
from utils.rnnclassifier import scope_decorator
from utils.rnnclassifier import weight_variable
from utils.session_iterator import BatchIterator as SessBatchIterator
from utils.SoSmodel import bias_variable
from utils.SoSmodel import get_available_gpus
from utils.SoSmodel import scope_decorator
from utils.SoSmodel import SoSModel
from utils.SoSmodel import weight_variable
from utils.training_utils import choose_regularization
from utils.training_utils import read_data
from utils.training_utils import select_features
from utils.training_utils import whiten_features
from utils.config import get_config


def test_Model():
    instance = Model(15)


def test_SoSModel():
    instance = SoSModel()


def test_BatchIterator():
    instance = BatchIterator({}, {})


def test_SessBatchIterator():
    instance = SessBatchIterator({}, {})


def test_AbnormalDetector():
    instnace = AbnormalDetector()


def test_is_private():
    private = is_private('192.168.0.1')
    assert private == True
    private = is_private('192.169.0.1')
    assert private == False
    private = is_private('10.0.0.1')
    assert private == True
    private = is_private('172.16.0.1')
    assert private == True
    private = is_private('172.33.0.1')
    assert private == False
    private = is_private('12.33.0.1')
    assert private == False
    private = is_private('fe80:00:1')
    assert private == True
    private = is_private('fd80:00:1')
    assert private == True
    private = is_private('21e0:fe80:00:1')
    assert private == False