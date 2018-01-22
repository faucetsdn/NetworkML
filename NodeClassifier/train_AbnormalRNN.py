import sys
import json
import logging
import pickle
import numpy as np
import tensorflow as tf
from utils.rnnclassifier import AbnormalDetector
from utils.training_data import create_dataset
from utils.iterator import BatchIterator

logging.basicConfig(level=logging.INFO)
tf.logging.set_verbosity(tf.logging.ERROR)

# Load info from config
with open('config.json') as config_file:
    config = json.load(config_file)
    rnn_size = config['rnn size']
    labels = config['labels']

def validation_cost(model, X_vala, L_vala, Y_vala):
    """
    Get the mean cost over length from the validation data
    """
    vala_costs = []
    for i in range(0,8-1+1):
        X_v, L_v, Y_v = X_vala[i], L_vala[i], Y_vala[i]
        c_v_s = model.get_cost(X_v,L_v,Y_v)
        vala_costs.append(c_v_s)
    return np.mean(vala_costs)

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
    iterator = BatchIterator(data, labels, perturb_types=['label_swap'])
    logger.info("Created iterator")
    rnnmodel = AbnormalDetector(num_labels=len(labels))
    logger.info("Created model")
    rnnmodel.initialize()
    logger.info("Initialized model")

    X_vala, L_vala, Y_vala = [], [], []
    for i in range(1,8+1):
        X_v, L_v, Y_v, _ = iterator.gen_batch(
                                                split='vala',
                                                length=i,
                                                batch_size=32
                                             )
        X_vala.append(X_v)
        L_vala.append(L_v)
        Y_vala.append(Y_v)
    logger.info("Generated validation data")

    cost = validation_cost(rnnmodel,X_vala,L_vala,Y_vala)
    logger.info("Initial validation cost: %s",np.mean(cost))
    for i in range(10):
        length = np.random.choice(range(1,9))
        X,L,Y,c = iterator.gen_batch(
                                        split='train',
                                        length=length,
                                        batch_size=128
                                    )
        _ = rnnmodel.train_on_batch(X,L,Y)
        if (i+1)%100 == 0:
            cost = validation_cost(rnnmodel,X_vala,L_vala,Y_vala)
            logger.info("Validation cost after  %s batches: %s",i,cost)
