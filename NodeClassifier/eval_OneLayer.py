'''
Reads a pcap and updates the stored representation of the source using
the one layer feedforward model.
'''

import json
import pika
import sys
import os
import ast
import logging
import hashlib
import numpy as np
import tensorflow as tf

from redis import StrictRedis
from utils.OneLayer import OneLayerModel
from utils.featurizer import is_private
from utils.reader import sessionizer
from utils.model_utils import clean_session_dict
from utils.model_utils import create_inputs
from rnnclassifier import AbnormalDetector

logging.basicConfig(level=logging.DEBUG)
tf.logging.set_verbosity(tf.logging.ERROR)
os.environ['TF_CPP_MIN_LOG_LEVEL'] ='3'

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

def lookup_key(key):
    '''
    Look up a key from the input filename
    '''
    try:
        r = StrictRedis(host='redis', port=6379, db=0)
        key_info = r.hgetall(key)
        endpoint = key_info[b'endpoint']
        endpoint = endpoint.decode('utf-8')
        end_dict = ast.literal_eval(endpoint)
        address = end_dict['ip-address']
    except Exception as e:
        address = None
        return address, e

    return address, None

def get_address_info(address, timestamp):
    '''
    Look up address information prior to the timestamp
    '''
    # Get the timestamps of the past updates for this address
    try:
        r = StrictRedis(host='redis', port=6379, db=0)
        updates = r.hgetall(address)
        timestamps = json.loads(updates[b'timestamps'].decode('ascii'))
    except Exception as e:
        timestamps = None

    # Defaults if there are no previous updates
    current_state = np.zeros(state_size)
    average_state = np.zeros(state_size)
    other_ips = []

    # If there is a previous update, read out the state
    last_update = None
    if timestamps is not None:
        # Get the most recent update prior to the current timestsmp
        updates = [time for time in timestamps if time < timestamp]
        if len(updates) > 0:
            last_update = max(updates)

    # Read the state of the most recent update if there was one
    if last_update is not None:
        key = address + '_' + str(last_update)
        state = r.hgetall(key)

        current_state = json.loads(
                            state[b'current_representation'].decode('ascii')
                                  )
        average_state = json.loads(state[b'representation'].decode('ascii'))
        labels = ast.literal_eval(state[b'labels'].decode('utf-8'))
        confs = ast.literal_eval(state[b'confidences'].decode('utf-8'))
        other_ips = ast.literal_eval(state[b'other_ips'].decode('utf-8'))
    else:
        labels = None
        confs = None

    return current_state, average_state, other_ips, last_update, labels, confs

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

def update_data(
                 source_ip,
                 representations,
                 timestamps,
                 predictions,
                 other_ips,
                 model_hash
               ):
    '''
    Updates the stored data with the new information

    Args:
        source_ip: Address of the representaion to update
        representations: New observations of representations
        timestamps: Time at which each representation was observed
        predictions: Model predictions along with confidences
        other_ips: Other IP addresses the source has communicated with
        model_hash: Hash of the model used to compute this information
    '''
    logger = logging.getLogger(__name__)

    try:
        r = StrictRedis(host='redis', port=6379, db=0)
    except:
        pass
    # Get the previous update time and average representation
    last_update, prev_rep = get_previous_state(source_ip, timestamps[0])

    # Compute current representation
    time, current_rep = average_representation(representations, timestamps)

    # Compute moving average representation
    time, avg_rep = average_representation(
                                            representations,
                                            timestamps,
                                            prev_representation=prev_rep,
                                            last_update=last_update
                                          )

    # Separate labels and confidences
    labels= [label for label, confidence in predictions]
    confidences = [confidence for label, confidence in predictions]

    # Create the information to store
    key = source_ip + '_' + str(time)
    state = {
                "representation": list(avg_rep),
                "current_representation": list(current_rep),
                "labels": labels,
                "confidences": confidences,
                "other_ips": sorted(other_ips),
                "model_hash": model_hash
            }

    logger.debug("Storing data")
    try:
        r.hmset(key, state)
    except Exception as e:
        logger.debug("created key %s", key)
        logger.debug(state)

    logger.debug("Storing update time")
    # Add this update time to the list of updates
    try:
        updates = r.hgetall(source_ip)
        update_list = json.loads(updates[b'timestamps'].decode('ascii'))
        logger.debug("Got previous updates from %s", source_ip)
    except Exception as e:
        logger.debug("No previous updates found for %s", source_ip)
        update_list = []

    update_list.append(time)
    update_list = sorted(update_list)
    times = { 'timestamps': update_list }
    logger.debug("Updating %s", source_ip)
    logger.debug(times)
    try:
        r.hmset(source_ip, times)
    except Exception as e:
        logger.debug("Could not store update time")

    return current_rep, avg_rep

def basic_decision(
                    key,
                    address,
                    prev_time,
                    timestamp,
                    labels,
                    confs,
                    abnormality
                  ):

    valid = True

    if labels is None:
        labels = ['Unknown']*3
        confs = [1,0,0]
        valid = False

    if key is None:
        key = address
        valid = False

    investigate = False
    if prev_time is not None and timestamp - prev_time > look_time:
        investigate = True
    if labels[0] == 'Unknown':
        investigate = True

    behavior = 'normal'
    if abnormality > threshold:
        behavior = 'abnormal'

    output = {}
    decisions = {'behavior': behavior, 'investigate': investigate}
    classifications = {'labels': labels[0:3], 'confidences': confs[0:3]}
    id_dict = {
                'decisions': decisions,
                'classification': classifications,
                'timestamp': timestamp,
                'valid': valid
              }
    output[key] = id_dict
    return output


if __name__ == '__main__':
    logger = logging.getLogger(__name__)

   # path to the pcap to get the update from
    pcap_path = sys.argv[1]
    # parse the filename to get IP address
    try:
        split_path = os.path.split(pcap_path)[-1]
        split_path = split_path.split('.')
        split_path = split_path[0].split('-')
        key = split_path[0].split('_')[1]
        key_address, _ = lookup_key(key)
        if len(split_path) >= 7:
            source_ip = '.'.join(split_path[-4:])
        else:
            source_ip = None
    except Exception as e:
        logger.debug("Could not get address info beacuse %s", e)
        logger.debug("Defaulting to inferring IP address from %s", pcap_path)
        source_ip = None
        key_address = None
    if key_address is None:
        key = None

    # extra check in case running the first time
    if ((split_path[-1] != 'miscellaneous' and key_address == source_ip) or
        (split_path[-1] != 'miscellaneous' and key_address == None)):
        # Initialize and load the model
        if len(sys.argv) > 2:
            load_path = sys.argv[2]
        else:
            load_path = os.path.join('models','OneLayerModel.pkl')

        # Compute model hash
        with open(load_path, 'rb') as handle:
            model_hash = hashlib.md5(handle.read()).hexdigest()

        model = OneLayerModel(duration=None, hidden_size=None)
        model.load(load_path)
        logger.debug("Loaded model from %s", load_path)

        # Get representations from the model
        reps, source_ip, timestamps, preds, others = model.get_representation(
                                                           pcap_path,
                                                           source_ip=source_ip,
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
            for session_dict in sessions:
                cleaned_sessions, inferred_ip = \
                            clean_session_dict(session_dict, source_ip=source_ip)
                clean_sessions.append(cleaned_sessions)

            if source_ip is None:
                source_ip = inferred_ip

            # Use the RNN model to compute abnormality scores
            rnnmodel = AbnormalDetector(
                                     packet_embedding_size=rnn_size,
                                     session_embedding_size=rnn_size,
                                     hidden_size=rnn_size//2,
                                     num_labels=len(mean_preds)
                                    )
            # Initialize and load the model
            if len(sys.argv) > 3:
                rnnpath= sys.argv[3]
            else:
                rnnpath = "/models/rnnmodel.ckpt"

            try:
                rnnmodel.load(rnnpath)
                abnormal_model = True
            except:
                abnormal_model = False
                abnormality = 0

            scores = []
            max_key = None
            max_score = 0
            if abnormal_model is True:
                # Group input sessions by number of packets
                inputs_by_length = [[] for i in range(8)]
                labels_by_length = [[] for i in range(8)]
                for session_dict in clean_sessions:
                    for k, session in session_dict.items():
                        X, L = create_inputs(mean_preds, session, 116)
                        length = X.shape[1]
                        if length <= 8:
                            inputs_by_length[length-1].append(X)
                            labels_by_length[length-1].append(L)
                # Evaluate sessions by length and by batch
                for i, sessions in enumerate(inputs_by_length):
                        labels = labels_by_length[i]
                        num_sessions = len(sessions)
                        num_batches = num_sessions//batch_size
                        for j in range(num_batches):
                            batch_sessions = sessions[j*batch_size:(j+1)*batch_size]
                            batch_labels = labels[j*batch_size:(j+1)*batch_size]
                            X = np.concatenate(batch_sessions, axis=0)
                            L = np.concatenate(batch_labels, axis=0)
                            model_out = rnnmodel.get_output(X,L)
                            scores.append(model_out[:,0])
                        if len(sessions[num_batches*batch_size:]) > 0:
                            batch_sessions = sessions[num_batches*batch_size:]
                            batch_labels = labels[num_batches*batch_size:]
                            X = np.concatenate(batch_sessions, axis=0)
                            L = np.concatenate(batch_labels, axis=0)
                            model_out = rnnmodel.get_output(X, L)
                            scores.append(model_out[:,0])
                try:
                    scores = np.concatenate(scores, axis=0)
                except:
                    scores = np.asarray([0])

                abnormality = np.max(scores)

            # Make simple decisions based on vector differences and update times
            decisions = {}
            timestamp = timestamps[0].timestamp()
            labels, confs = zip(*preds)
            repr_s, m_repr_s, _ , prev_s, _, _ = get_address_info(
                                                                   source_ip,
                                                                   timestamp
                                                                 )
            decision = basic_decision(
                                       key,
                                       source_ip,
                                       prev_s,
                                       timestamp,
                                       labels,
                                       confs,
                                       abnormality
                                     )
            logger.debug("Created message")
            for i in range(3):
                logger.debug(labels[i] + ' : ' + str(round(confs[i],3)))
            # Get json message
            message = json.dumps(decision)

            # Get our "SKIP_RABBIT" environment variable with a default value of
            # false
            skip_rabbit = os.getenv("SKIP_RABBIT", "False")

            # Convert our string into a boolean
            skip_rabbit = skip_rabbit.lower() in ["true", "t", "y", "1"]

            logger.debug("SKIP_RABBIT set to: %s", str(skip_rabbit))

            if skip_rabbit:
                # Rabbit settings
                exchange = 'topic-poseidon-internal'
                exchange_type = 'topic'

                # Starting rabbit connection
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(host='rabbit')
                )

                channel = connection.channel()
                channel.exchange_declare(
                    exchange=exchange, exchange_type=exchange_type
                )

                routing_key = 'poseidon.algos.decider'
                channel.basic_publish(exchange=exchange,
                                      routing_key=routing_key,
                                      body=message)
                logger.debug("Routing key: " + routing_key)
                logger.debug("Exchange: " + exchange)
                connection.close()
            else:
                # Skipping rabbit. Printing to STDOUT
                logger.info("Message: " + message)
        else:
            logger.info("Not enough sessions in pcap")
