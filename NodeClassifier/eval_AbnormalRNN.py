import os
import sys
import json
import numpy as np
from utils.RandomForestModel import RandomForestModel
from utils.rnnclassifier import AbnormalDetector
from utils.pcap_utils import is_private, clean_session_dict, create_inputs
import tensorflow as tf
import logging

logging.basicConfig(level=logging.INFO)
tf.logging.set_verbosity(tf.logging.ERROR)
logger = logging.getLogger(__name__)

# Get time constant from config
with open('config.json') as config_file:
    config = json.load(config_file)
    time_const = config['time constant']
    state_size = config['state size']
    duration = config['duration']
    look_time = config['look time']
    threshold = config['threshold']
    batch_size = config['batch size']
    rnn_size = config['rnn size']
    labels = config['labels']

def get_previous_state(source_ip, timestamp):
    '''
    Gets the average representation vector from the most recent update
    before the current timestamp

    Args:
        source_ip: IP address to read the representation from
        timestamp: Current timestamp.  Get only representations before this

    Returns:
        last_update: Timestamp of last update
        previous_representation: Average representation at last update
    '''

    # Try to read the old updates, if there are none return Nones
    try:
        r = StrictRedis(host='redis', port=6379, db=0)
        updates = r.hgetall(source_ip)
    except Exception as e:
        return None, None

    # Get the most recent prior timestamp from the update list
    try:
        update_list = json.loads(updates[b'timestamps'].decode('ascii'))
    except:
        update_list = []
    last_update = None
    for update in update_list:
        if update < timestamp.timestamp():
            last_update = update

    # Return Nones if there is no earlier update
    if last_update is None:
        return None, None

    # Read the last updated entry to get the previous representation
    key = source_ip + '_' + str(last_update)
    try:
        state = r.hgetall(key)
    except Exception as e:
        return None, None
    previous_representation = json.loads(
                                       state[b'representation'].decode('ascii')
                                        )
    return last_update, previous_representation

def average_representation(
                            representations,
                            timestamps,
                            prev_representation=None,
                            last_update=None,
                          ):
    '''
    Computes the new representation from the old ones if they are given.
    If they are not, compute the EMA of the new observations

    Args:
        representations: New representations
        timestamps: Times that the new representations were seen
        prev_representation: The representation computed at last_update
        last_update: Time of previous representation update

    Returns:
        new_timestamp: Timestamp of the new representations
        new_representation: Newly computed representations
    '''

    # If there is no previous representation, default to zeros
    if prev_representation is None:
        last_update = None
        prev_representation = np.zeros(representations.shape[1])

    prev_time = last_update
    representation = prev_representation
    for i, rep in enumerate(representations):
        time = timestamps[i].timestamp()
        # If there was no previous update the representation is set equal to
        # the current representaton
        if  prev_time is None:
            representation = rep
            prev_time = time
        # If the time of the representation is after the previous update,
        # compute the exponentially weighted moving average.
        elif time > prev_time:
            time_diff = time - prev_time
            alpha = 1 - np.exp(-time_diff/time_const)
            representation += alpha*(rep - representation)
            prev_time = time

    return time, representation

def eval_rnn(pcap, input_label=None):
    '''
    Evaluate the RNN model on a single pcap
    '''
    load_path = '/models/RandomForestModel.pkl'
    model = RandomForestModel(duration=None)
    model.load(load_path)

    # Get representations from the model
    reps, source_ip, timestamps, preds, others = model.get_representation(
                                                       pcap_path,
                                                       source_ip=None,
                                                       mean=False
                                                                         )

    if preds is not None:
        logger.debug("Generating predictions")
        last_update, prev_rep = get_previous_state(source_ip, timestamps[0])
        _, mean_rep = average_representation(
                                                reps,
                                                timestamps,
                                                prev_representation=prev_rep,
                                                last_update=last_update
                                            )
        mean_preds = model.classify_representation(mean_rep)
        if len(sys.argv) > 2:
            for p in mean_preds:
                logger.debug(p)
        # Update the stored representation
        current_rep, avg_rep = None, None
        if reps is not None and is_private(source_ip):
            logger.debug("Updating stored data")
            current_rep, avg_rep = update_data(
                                                source_ip,
                                                reps,
                                                timestamps,
                                                preds,
                                                others,
                                                model_hash
                                               )

        # Get the sessions that the model looked at
        sessions = model.sessions
        # Clean the sessions
        clean_sessions = []
        inferred_ip = None


        clean_sessions, inferred_ip = \
                    clean_session_dict(
                                        sessions,
                                        source_address=None
                                      )

        if source_ip is None:
            source_ip = inferred_ip

        L_in = []
        pred_labels = {l[0]:l[1] for l in mean_preds}
        if input_label is None:
            for l in labels:
                if l not in pred_labels:
                    L_in.append((l,0))
                else:
                    L_in.append((l,pred_labels[l]))
        else:
            L_in = [(l,0) for l in labels if l != input_label]
            L_in.append((input_label,1))

        # Use the RNN model to compute abnormality scores
        rnnmodel = AbnormalDetector(num_labels=len(labels))
        rnnpath = '/models/AbnormalRNN'
        rnnmodel.load(rnnpath)

        for session_dict in clean_sessions:
            for k, session in session_dict.items():
                X, L = create_inputs(L_in, session, 116)
                score = rnnmodel.get_output(X, L)
                print(k, score[0,0])

if __name__ =='__main__':
    pcap_path = sys.argv[1]
    if len(sys.argv) == 3:
        input_label = sys.argv[2]
    else:
        input_label = None
    s = eval_rnn(pcap_path, input_label=input_label)
    print(s)
