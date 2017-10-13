'''
Reads a pcap, parses it into sessions, and classifies the sessions as being
either normal or abnormal using the specified model
'''

import sys
import os
import logging
from redis import StrictRedis
import numpy as np

from reader import sessionizer
from featurizer import is_private
from model_utils import clean_session_dict
from classifier import Classifier

import json
import pika

# Load parameters from config
with open('config.json') as config_file:
    config = json.load(config_file)
state_size = config['state size']
duration = config['duration']
look_time = config['look time']
threshold = config['threshold']

logging.basicConfig(level=logging.INFO)

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
        key = address + '_' + str(timestamp)
        try:
            state = r.hgetall(key)
        except Exception as e:
            return current_state, average_state, other_ips, last_update

        current_state = json.loads(
                            state[b'current_representation'].decode('ascii')
                                  )
        average_state = json.loads(state[b'representation'].decode('ascii'))
        labels = json.loads(state[b'labels']).decode('ascii')
        confs = json.loads(state[b'confidences']).decode('ascii')
        other_ips = json.loads(state[b'other_ips'].decode('ascii'))
    else:
        labels = None
        confs = None

    return current_state, average_state, other_ips, last_update, labels, confs

def basic_decision(
                    key,
                    address,
                    current_rep,
                    mean_rep,
                    prev_time,
                    timestamp,
                    labels,
                    confs
                  ):

    if key is None:
        key = address

    if labels is None:
        labels = ['Unknown']*3
        confs = [1,0,0]

    investigate = False
    if prev_time is None or timestamp - prev_time > look_time:
        investigate = True

    behavior = 'normal'
    if np.dot(current_rep, mean_rep) < threshold:
        behavior = 'abnormal'

    output = {}
    decisions = {'behavior': 'normal', 'investigate': False}
    classifications = {'labels': labels[0:3], 'confidences': confs[0:3]}
    id_dict = {
                'decisions': decisions,
                'classification': classifications,
                'timestamp': timestamp
              }
    output[key] = id_dict
    return output

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    # Get the pcap path from the first argument
    pcap_path = sys.argv[1]
    # Determine the source IP address from filename
    split_path = os.path.split(pcap_path)[-1]
    split_path = split_path.split('.')
    split_path = split_path[0].split('-')
    key = split_path[0].split('_')[1]
    if len(split_path) >= 7:
        source_ip = '.'.join(split_path[-4:])
    else:
        source_ip = None

    # Parse the pcap into sessions
    sessions, timestamp = sessionizer(pcap_path, duration=duration)

    # Clean the sessions
    cleaned_sessions = []
    inferred_ip = None
    for session_dict in sessions:
        cleaned_sessions, inferred_ip = \
                        clean_session_dict(session_dict, source_ip=source_ip)
    if source_ip is None:
        source_ip = inferred_ip

    if is_private(source_ip):
        # Laad the model 
        if len(sys.argv) > 2:
            model_path = sys.argv[2]
        else:
            model_path = 'models/RNNmodel.h5'
        #model = RNNClassifier()
        #model.load(model_path)

        # Make simple decisions based on vector differences and update times
        decisions = {}
        repr_s, m_repr_s, _ , prev_s, labels, confs = get_address_info(
                                                                     source_ip,
                                                                     timestamp
                                                                      )
        decision = basic_decision(
                                   key,
                                   source_ip,
                                   repr_s,
                                   m_repr_s,
                                   prev_s,
                                   timestamp,
                                   labels,
                                   confs
                                 )
        message = json.dumps(decision)
        logger.info("Created message")
        logger.info(decision)

        # Create connection to rabbitmq
        try:
            host = None
            port = None
            rabbit_connection = pika.BlockingConnection(
                               pika.ConnectionParameters(host=host, port=port))
            rabbit_channel = rabbit_connection.channel()
            rabbit_channel.queue_declare(queue='poseidon_AI')
            logger.info("Connection created")
        except Exception as e:
            logger.info("Could not create connection")
            logger.info(e)

        # Send message to poseion AI channel
        try:
            rabbit_channel.basic_publish(
                                       exchange='topic-poseidon-internal',
                                       routing_key='poseidon.algos.ML.results',
                                       body=message
                                        )
            logger.info("Sent message")
            rabbit_connection.close()
        except Exception as e:
            logger.info("Could not send message")
            logger.info(e)
