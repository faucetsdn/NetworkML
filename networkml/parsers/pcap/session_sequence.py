"""
Generates a training set for training an abnormality detection model from the
data directory specified by the first argument.  This uses the representations
obtained from a device classifier model specified by the second argument to
condition on
"""
import logging
import os
import pickle
import sys

import numpy as np

from networkml.parsers.pcap.pcap_utils import featurize_session
from networkml.parsers.pcap.pcap_utils import get_source
from networkml.utils.model import Model


logging.basicConfig(level=logging.INFO)


def average_representation(rep, timestamp, prev_rep, prev_time, time_const):
    """
    Computes the new moving average representation from a single input
    """

    # If no previous info, the average is just the input
    if prev_rep is None or prev_time is None:
        return rep, timestamp

    # Otherwise, compute the moving average
    delta_t = timestamp.timestamp() - prev_time.timestamp()
    alpha = 1 - np.exp(-delta_t/time_const)
    new_rep = prev_rep + alpha*(rep - prev_rep)

    return new_rep, timestamp


def create_dataset(
    data_dir,
    time_const,
    model_path='networkml/trained_models/onelayer/OneLayerModel.pkl',
    label=None,
    model_type='randomforest'
):
    logger = logging.getLogger(__name__)
    try:
        if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        logger.error(
            'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))

    # Load the model
    logger.debug('Loading model')
    model = Model(duration=None, hidden_size=None, model_type=model_type)
    model.load(model_path)

    # Get all the pcaps in the training directory
    logger.debug('Getting pcaps')
    pcaps = []
    try:
        ext = os.path.splitext(data_dir)[-1]
        if ext == '.pcap':
            pcaps.append(data_dir)
    except Exception as e:
        logger.debug('Skipping {0} because: {1}'.format(data_dir, str(e)))

    for dirpath, _, filenames in os.walk(data_dir):
        for filename in filenames:
            ext = os.path.splitext(filename)[-1]
            if ext == '.pcap':
                pcaps.append(os.path.join(dirpath, filename))

    # Get and store the representations using the supplied model
    # Representations will be computed separately for each pcap
    representations = {}
    count = 0
    for pcap in pcaps:
        count += 1
        logger.info('Working on {0} ({1} bytes) ({2}/{3})'.format(pcap,
                                                                  os.path.getsize(pcap), str(count), len(pcaps)))
        reps, _, timestamps, _, _, _ = model.get_representation(
            pcap,
            mean=False
        )
        sessions = model.sessions

        # Compute the mean representations
        prev_rep = None
        prev_time = None
        model_outputs = {}

        if timestamps is not None:
            for i, timestamp in enumerate(timestamps):
                rep = reps[i]
                new_rep, time = average_representation(
                    rep,
                    timestamp,
                    prev_rep,
                    prev_time,
                    time_const
                )
                preds = model.classify_representation(new_rep)
                if label is not None:
                    preds = [(p[0], 0) for p in preds if p[0] != label]
                    preds.append((label, 1))

                model_outputs[timestamp] = {
                    'classification': list(preds),
                    'representation': list(rep),
                    'mean representation': list(new_rep)
                }
                prev_rep, prev_time = new_rep, time

        # Clean the sessions and merge them into a single session dict
        session_rep_pairs = []
        source = get_source(sessions, address_type='IP')
        for session_dict in sessions:
            for key, value in session_dict.items():
                session_info = featurize_session(key, value, source=source)

                first_time = value[0][0].timestamp()
                prior_time = None
                for timestamp in timestamps:
                    time = timestamp.timestamp()
                    if first_time > time:
                        prior_time = timestamp
                if prior_time == None:
                    prior_time = timestamps[0]

                pair = {
                    'model outputs': model_outputs[prior_time],
                    'session info': session_info,
                    'key': key
                }
                if session_info is not None:
                    session_rep_pairs.append(pair)

        representations[pcap] = session_rep_pairs
    byte_size = sys.getsizeof(pickle.dumps(representations))
    logger.debug(
        'created training data of size %f mb',
        round(byte_size/1000000, 3)
    )

    return representations
