import logging
import os

import numpy as np

from networkml.algorithms.sos.SoSmodel import SoSModel
from networkml.parsers.pcap.session_iterator import BatchIterator
from networkml.parsers.pcap.session_sequence import create_dataset


logging.basicConfig(level=logging.INFO)


# TODO this should be re-written to follow patterns from onelayer/randomforest
def eval_pcap(pcap, labels, time_const, label=None, rnn_size=100, model_path='networkml/trained_models/onelayer/OneLayerModel.pkl', model_type='randomforest'):
    logger = logging.getLogger(__name__)
    try:
        if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        logger.error(
            'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))
    data = create_dataset(pcap, time_const, label=label,
                          model_path=model_path, model_type=model_type)
    # Create an iterator
    iterator = BatchIterator(
        data,
        labels,
        perturb_types=['random data']
    )
    logger.debug('Created iterator')
    rnnmodel = SoSModel(rnn_size=rnn_size, label_size=len(labels))
    logger.debug('Created model')
    rnnmodel.load('networkml/trained_models/sos/SoSmodel')
    logger.debug('Loaded model')

    X_list = iterator.X
    L_list = iterator.L
    sessions = iterator.sessions

    num_total = 0
    max_score = 0
    scores = {}
    for i, X in enumerate(X_list):
        L = L_list[i]
        out = rnnmodel.get_output(
            np.expand_dims(X, axis=0),
            np.expand_dims(L, axis=0),
        )
        for _, o in enumerate(out):
            for k, s in enumerate(o):
                num_total += 1
                session = sessions[i][k]['session info']
                p = session['protocol']
                if p == '06':
                    p = 'TCP'
                if p == '17':
                    p = 'UDP'
                if p == '01':
                    p = 'ICMP'
                flowlike = p + ' '
                if session['initiated by source']:
                    flowlike += session['source']+' to '+session['destination']
                else:
                    flowlike += session['destination']+' to '+session['source']
                scores[num_total] = str(s)
                if s > max_score:
                    max_score = s

    logger.info(max_score)
    return max_score
