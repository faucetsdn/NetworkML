import logging
import os
import pickle

import numpy as np

from networkml.algorithms.sos.SoSmodel import SoSModel
from networkml.parsers.pcap.session_iterator import BatchIterator
from networkml.parsers.pcap.session_sequence import create_dataset

logging.basicConfig(level=logging.INFO)


def train(data_dir, time_const, rnn_size, labels, save_path):
    logger = logging.getLogger(__name__)
    try:
        if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        logger.error(
            'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))

    data = create_dataset(data_dir, time_const)
    # Create the training data
    logger.info('Saving data to %s', save_path)
    with open(save_path, 'wb') as handle:
        pickle.dump(data, handle, protocol=pickle.HIGHEST_PROTOCOL)

    logger.info('Loaded training data')
    # Create an iterator
    iterator = BatchIterator(
        data,
        labels,
        perturb_types=['random data', 'port swap', 'direction_swap']
    )
    logger.info('Created iterator')
    rnnmodel = SoSModel(rnn_size=100, label_size=len(labels))
    logger.info('Created model')
    try:
        rnnmodel.load('networkml/trained_models/sos/SoSmodel')
        logger.info('Loaded model')
    except Exception as e:
        rnnmodel.initialize()
        logger.info('Initialized model')

    X_v, L_v, Y_v = iterator.gen_batch(
        split='validation',
        batch_size=64
    )

    cost = rnnmodel.get_cost(X_v, L_v, Y_v)

    logger.info('Initial validation cost: %s', np.mean(cost))
    rnnmodel.save('networkml/trained_models/sos/SoSmodel')
    logger.info('Saving model at validation cost %s', cost)
    min_cost = cost
    last_save = 0
    for i in range(100000):
        X, L, Y = iterator.gen_batch(
            split='train',
            batch_size=64
        )
        _ = rnnmodel.train_on_batch(X, L, Y)
        if (i+1) % 100 == 0:
            cost = rnnmodel.get_cost(X_v, L_v, Y_v)
            logger.info('Validation cost after  %s batches: %s', i, cost)
            if cost < min_cost:
                min_cost = cost
                rnnmodel.save('networkml/trained_models/sos/SoSmodel')
                last_save = 0
                logger.info('Saving model at validation cost %s', cost)
            else:
                last_save += 100
        if last_save > 1000:
            logger.info('No improvement after 1000 iterations. Stopping.')
            break
