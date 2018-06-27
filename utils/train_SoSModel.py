import os
import sys
import json
import logging
import pickle
import numpy as np
import tensorflow as tf
from .SoSmodel import SoSModel
from .session_sequence import create_dataset
from .session_iterator import BatchIterator
import time

logging.basicConfig(level=logging.INFO)
tf.logging.set_verbosity(tf.logging.ERROR)

# Load info from config
with open('opts/config.json') as config_file:
    config = json.load(config_file)
    rnn_size = config['rnn size']
    labels = config['labels']

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    # Path to training data
    data_dir = sys.argv[1]
    # Create the training data
    if len(sys.argv) == 3:
        data = create_dataset(data_dir)
        write_dir = sys.argv[2]
        logger.info("Saving data to %s", write_dir)
        with open(write_dir, 'wb') as handle:
            pickle.dump(data, handle, protocol=pickle.HIGHEST_PROTOCOL)
    else:
        data = data_dir

    logger.info("Loaded training data")
    # Create an iterator
    iterator = BatchIterator(
                             data,
                             labels,
                             perturb_types=['random data','port swap', 'direction_swap']
                            )
    logger.info("Created iterator")
    rnnmodel = SoSModel(rnn_size=100)
    logger.info("Created model")
    try:
        rnnmodel.load(os.path.join('models','SoSmodel'))
        logger.info("Loaded model")
    except:
        rnnmodel.initialize()
        logger.info("Initialized model")

    X_v, L_v, Y_v = iterator.gen_batch(
                                            split='validation',
                                            batch_size=64
                                         )

    cost = rnnmodel.get_cost(X_v,L_v,Y_v)
    out = rnnmodel.get_output(X_v, L_v)

    logger.info("Initial validation cost: %s",np.mean(cost))
    min_cost = cost
    last_save = 0
    for i in range(100000):
        tick = time.clock()
        X,L,Y = iterator.gen_batch(
                                    split='train',
                                    batch_size=64
                                  )
        tock = time.clock()
        _ = rnnmodel.train_on_batch(X,L,Y)
        if (i+1)%100 == 0:
            cost = rnnmodel.get_cost(X_v,L_v,Y_v)
            logger.info("Validation cost after  %s batches: %s",i,cost)
            if cost < min_cost:
                min_cost = cost
                rnnmodel.save(os.path.join('models','SoSmodel'))
                last_save = 0
                logger.info('Saving model at validation cost %s', cost)
            else:
                last_save += 100
        if last_save > 1000:
            logger.info("No improvement after 1000 iterations. Stopping.")
            break
