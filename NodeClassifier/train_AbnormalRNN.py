import sys
import json
import logging
import numpy as np
from utils.rnnclassifier import AbnormalDetector
from utils.training_data import create_dataset
from utils.iterator import BatchIterator

logging.basicConfig(level=logging.INFO)

# Load info from config
with open('config.json') as config_file:
    config = json.load(config_file)
    rnn_size = config['rnn size']
    labels = config['labels']

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    # Path to training data
    data_dir = sys.argv[1]
    # Create the training data
    data = create_dataset(data_dir)
    logger.info("Created training data")
    # Create an iterator
    iterator = BatchIterator(data, labels, perturb_types=[''])
    logger.info("Created iterator")
    rnnmodel = AbnormalDetector(num_labels=len(labels))
    logger.info("Created model")
    rnnmodel.initialize()
    logger.info("Initialized model")
    X,L,Y,c = iterator.gen_batch()
    cost = rnnmodel.train_on_batch(X,L,Y)
    logger.info("Trained one batch for cost ",np.mean(cost))
    cost = rnnmodel.train_on_batch(X,L,Y)
    logger.info("Trained two batch for cost ",np.mean(cost))
