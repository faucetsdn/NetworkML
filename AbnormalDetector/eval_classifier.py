'''
Reads a pcap, parses it into sessions, and classifies the sessions as being
either normal or abnormal using the specified model
'''

import sys
import os
from redis import StrictRedis
import numpy as np

from reader import sessionizer
from model_utils import clean_session_dict
from RNNClassifier import RNNClassifier

# HYPERPARAMETERS 
state_size = 32
duration = 900
look_time = 24*68*60

def get_address_info(address, timestamp):
    '''
    Look up address information prior to the timestamp
    '''
    # Get the timestamps of the past updates for this address
    try:
        r = StrictRedis(host='redis', port=6379, db=0)
        timestamps = r.hgetall(address)
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
        key = address + '_' + str(timestamp)
        try:
            state = r.hgetall(key)
        except Exception as e:
            return current_state, average_state, other_ips, last_update

        current_state = json.loads(
                            state[b'current_representation'].decode('ascii')
                                  )
        average_state = json.loads(state[b'representation'].decode('ascii'))
        other_ips = json.loads(state[b'other_ips'].decode('ascii'))

    return current_state, average_state, other_ips, last_update

def basic_decision(address, current_rep, mean_rep, prev_time, timestamp):
    decisions = {'Abnormal': False, 'Investigate': False}
    if prev_time is None or timestamp - prev_time > look_time:
        decisions['Investigate'] = True
    if np.dot(current_rep, mean_rep) < 0:
        decisions['Abnormal'] = True
    return decisions

if __name__ == '__main__':
    # Get the pcap path from the first argument
    pcap_path = sys.argv[1]
    # Determine the source IP address from filename
    split_path = os.path.split(pcap_path)[-1]
    split_path = split_path.split('.')
    split_path = split_path[0].split('-')
    if len(split_path) >= 7:
        source_ip = '.'.join(split_path[-4:])
    else:
        source_ip = None

    # Parse the pcap into sessions
    sessions, timestamp = sessionizer(pcap_path, duration=duration)

    # Clean the sessions
    cleaned_sessions = []
    for session_dict in sessions:
        cleaned_sessions, inferred_ip = \
                        clean_session_dict(session_dict, source_ip=source_ip)
    if source_ip is None:
        source_ip = inferred_ip

    # Laad the model 
    if len(sys.argv) > 2:
        model_path = sys.argv[2]
    else:
        model_path = 'models/RNNmodel.h5'
    #model = RNNClassifier()
    #model.load(model_path)

    # Run each session through the model
    other_ips = []
    for key, packets in cleaned_sessions.items():
        address_1 = key[0].split(':')[0]
        address_2 = key[1].split(':')[0]
        if address_1 != source_ip and address_1 not in other_ips:
            other_ips.append(address_1)
        if address_2 != source_ip and address_2 not in other_ips:
            other_ips.append(address_2)

        # Get timestamp of first packet
        timestamp = packets[0][0].timestamp()
        # Get the representation vectors for each address
        repr_1, m_repr_1, _, prev_1 = get_address_info(address_1, timestamp)
        repr_2, m_repr_2, _, prev_2 = get_address_info(address_2, timestamp)
        # Encode packets
        #X_in = create_inputs(packets)
        # Feed inputs through the model to get classification
        #classification = model.predict(X_in, repr_1, repr_2)
        #classifications.append([address_1,address_2,classification])

    # Make simple decisions based on vector differences and update times
    decisions = {}
    repr_s, m_repr_s, _ , prev_s = get_address_info(source_ip, timestamp)
    decisions[source_ip] = basic_decision(
                                            source_ip,
                                            repr_s,
                                            m_repr_s,
                                            prev_s,
                                            timestamp
                                         )
    for other_ip in other_ips:
        repr_o, m_repr_o, _, prev_o = get_address_info(other_ip, timestamp)
        decisions[other_ip] = basic_decision(
                                              other_ip,
                                              repr_o,
                                              m_repr_o,
                                              prev_o,
                                              timestamp
                                            )


    # Here is where the decision dictionary should be passed to poseidon
    for key, item in decisions.items():
        print(key, item)
    print(decisions)
