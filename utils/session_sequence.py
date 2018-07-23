"""
Generates a training set for training an abnormality detection model from the
data directory specified by the first argument.  This uses the representations
obtained from a device classifier model specified by the second argument to
condition on
"""

import logging
import numpy as np
import os
import pickle
import sys

try:
    from .RandomForestModel import RandomForestModel
    from .pcap_utils import get_source
    from .pcap_utils import featurize_session
except SystemError:
    from RandomForestModel import RandomForestModel
    from pcap_utils import get_source
    from pcap_utils import featurize_session

logging.basicConfig(level=logging.INFO)


def average_representation(rep, timestamp, prev_rep, prev_time, time_const):
    """
    Computes the new moving average representation from a single input
    """

    # If no previous info, the average is just the input
    if prev_rep is None or prev_time is None:
        return rep, timestamp

    #Otherwise, compute the moving average
    delta_t = timestamp.timestamp() - prev_time.timestamp()
    alpha = 1 - np.exp(-delta_t/time_const)
    new_rep = prev_rep + alpha*(rep - prev_rep)

    return new_rep, timestamp

def create_dataset(
                    data_dir,
                    time_const,
                    model_path='/models/OneLayerModel.pkl',
                    label=None
                  ):
    logger = logging.getLogger(__name__)
    try:
        if "LOG_LEVEL" in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        print("Unable to set logging level because: {0} defaulting to INFO.".format(str(e)))

    # Load the model
    logger.debug("Loading model")
    model = RandomForestModel(duration=None, hidden_size=None)
    model.load(model_path)

    # Get all the pcaps in the training directory
    logger.debug("Getting pcaps")
    pcaps = []
    try:
        name, ext = os.path.splitext(data_dir)
        if ext == '.pcap':
            pcaps.append(data_dir)
    except:
        pass

    for dirpath, dirnames, filenames in os.walk(data_dir):
        for filename in filenames:
            name, ext = os.path.splitext(filename)
            if ext == '.pcap':
                pcaps.append(os.path.join(dirpath,filename))

    # Get and store the representations using the supplied model
    # Representations will be computed separately for each pcap
    representations = {}
    for pcap in pcaps:
        logger.debug("Working on %s", pcap)
        reps, _, timestamps, _, _ = model.get_representation(
                                                            pcap,
                                                            mean=False
                                                                    )
        sessions = model.sessions
        source_address = get_source(sessions)

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
                    preds = [(p[0],0) for p in preds if p[0] != label]
                    preds.append((label,1))

                model_outputs[timestamp] = {
                                            "classification": list(preds),
                                            "representation": list(rep),
                                            "mean representation": list(new_rep)
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
                        "model outputs": model_outputs[prior_time],
                        "session info": session_info,
                        "key": key
                       }
                if session_info is not None:
                    session_rep_pairs.append(pair)

        representations[pcap] = session_rep_pairs
    byte_size = sys.getsizeof(pickle.dumps(representations))
    logger.debug(
                "created training data of size %f mb",
                round(byte_size/1000000, 3)
               )

    return representations
