import json
import logging
import numpy as np
import os
import pickle
import sys
import tensorflow as tf
import time

try:
   from .SoSmodel import SoSModel
   from .session_sequence import create_dataset
   from .session_iterator import BatchIterator
except SystemError:
   from SoSmodel import SoSModel
   from session_sequence import create_dataset
   from session_iterator import BatchIterator


logging.basicConfig(level=logging.INFO)
tf.logging.set_verbosity(tf.logging.ERROR)
os.environ['TF_CPP_MIN_LOG_LEVEL'] ='3'


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    try:
        if "LOG_LEVEL" in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        print("Unable to set logging level because: {0} defaulting to INFO.".format(str(e)))

    # Load info from config
    with open('opts/config.json') as config_file:
        config = json.load(config_file)
        time_const = config['time constant']
        rnn_size = config['rnn size']
        labels = config['labels']

    # Path to training data
    data_dir = sys.argv[1]
    # Create the training data
    if len(sys.argv) == 3:
        data = create_dataset(data_dir, time_const)
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
    rnnmodel = SoSModel(rnn_size=100, label_size=len(labels))
    logger.info("Created model")
    try:
        rnnmodel.load('/models/SoSmodel')
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
                rnnmodel.save('/models/SoSmodel')
                last_save = 0
                logger.info('Saving model at validation cost %s', cost)
            else:
                last_save += 100
        if last_save > 1000:
            logger.info("No improvement after 1000 iterations. Stopping.")
            break
