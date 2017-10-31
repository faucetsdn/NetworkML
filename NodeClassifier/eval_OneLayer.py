'''
Reads a pcap and updates the stored representation of the source using
the one layer feedforward model.
'''

import json
import sys
import os
import logging
import hashlib
import numpy as np

from redis import StrictRedis
from OneLayer import OneLayerModel
from featurizer import is_private

logging.basicConfig(level=logging.INFO)

# Get time constant from config
with open('config.json') as config_file:
    config = json.load(config_file)
    time_const = config['time constant']

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

    logger.info("Storing data")
    try:
        r.hmset(key, state)
    except Exception as e:
        logger.info("created key %s", key)
        logger.info(state)

    logger.info("Storing update time")
    # Add this update time to the list of updates
    try:
        updates = r.hgetall(source_ip)
        update_list = json.loads(updates[b'timestamps'].decode('ascii'))
        logger.info("Got previous updates from %s", source_ip)
    except Exception as e:
        logger.info("No previous updates found for %s", source_ip)
        update_list = []

    update_list.append(time)
    update_list = sorted(update_list)
    times = { 'timestamps': update_list }
    logger.info("Updating %s", source_ip)
    logger.info(times)
    try:
        r.hmset(source_ip, times)
    except Exception as e:
        logger.info("Could not store update time")

if __name__ == '__main__':
    logger = logging.getLogger(__name__)

   # path to the pcap to get the update from
    pcap_path = sys.argv[1]
    # parse the filename to get IP address
    split_path = os.path.split(pcap_path)[-1]
    split_path = split_path.split('.')
    split_path = split_path[0].split('-')
    key = split_path[0].split('_')[1]
    key_address, _ = lookup_key(key)
    if len(split_path) >= 7:
        source_ip = '.'.join(split_path[-4:])
    else:
        logger.info("Defaulting to inferring IP address from %s", pcap_path)
        source_ip = None

    if split_path[-1] != 'miscellaneous' and key_address == source_ip:
        # Initialize and load the model
        if len(sys.argv) > 2:
            load_path = sys.argv[2]
        else:
            load_path = "/models/model.pickle"

        # Compute model hash
        with open(load_path, 'rb') as handle:
            model_hash = hashlib.md5(handle.read()).hexdigest()

        model = OneLayerModel(duration=None, hidden_size=None)
        model.load(load_path)
        logger.info("Loaded model from %s", load_path)

        # Get representations from the model
        reps, source_ip, timestamps, preds, others = model.get_representation(
                                                           pcap_path,
                                                           source_ip=source_ip,
                                                           mean=False
                                                                             )

        logger.info("Generating predictions")
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
                logger.info(p)
        # Update the stored representation
        if reps is not None and is_private(source_ip):
            logger.info("Updating stored data")
            update_data(source_ip, reps, timestamps, preds, others, model_hash)
