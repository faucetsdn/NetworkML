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
        if update < timestamp:
            last_update = update

    # Return Nones if there is no earlier update
    if last_update is None:
        return None, None

    # Read the last updated entry to get the previous representation
    key = source_ip + '_' + str(last_update)
    try:
        previous_state = r.hgetall(key)
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

    # Set the time constant to one day
    time_const = 60*60*24

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
    logging.basicConfig(level=logging.INFO)
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
    try:
        r.hmset(key, state)
    except Exception as e:
        logger.info("created key %s", key)
        logger.info(state)

    # Add this update time to the list of updates
    try:
        updates = r.hgetall(source_ip)
        update_list = json.loads(updates[b'timestamps'].decode('ascii'))
        update_list.append(time)
        times = { 'timestamps': update_list }
        r.hmset(source_ip, times)
    except Exception as e:
        pass

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

   # path to the pcap to get the update from
    pcap_path = sys.argv[1]
    # parse the filename to get IP address
    split_path = os.path.split(pcap_path)[-1]
    split_path = split_path.split('.')
    split_path = split_path[0].split('-')
    if len(split_path) >= 7:
        source_ip = '.'.join(split_path[-4:])
    else:
        logger.info("Defaulting to inferring IP address")
        source_ip = None

    if split_path[-1] != 'miscellaneous' and source_ip != '255.255.255.255':
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

        if len(sys.argv) > 2:
            logger.info("Generating predictions")
            _, mean_rep = average_representation(reps, timestamps)
            mean_preds = model.classify_representation(mean_rep)
            for p in mean_preds:
                logger.info(p)
        # Update the stored representation
        if reps is not None and is_private(source_ip):
            logger.info("Updating stored data")
            update_data(source_ip, reps, timestamps, preds, others, model_hash)
