import ast
import hashlib
import json
import logging
import os
import sys

import numpy as np
import pika
import tensorflow as tf
from poseidonml.eval_SoSModel import eval_pcap
from poseidonml.OneLayer import OneLayerModel
from poseidonml.pcap_utils import clean_session_dict
from redis import StrictRedis


class OneLayerEval:
    """
    Reads a pcap and updates the stored representation of the source using
    the one layer feedforward model.
    """

    def __init__(self):
        self.r = None
        self.time_const = None
        self.state_size = None
        self.look_time = None
        self.threshold = None
        self.conf_labels = None
        self.rnn_size = None

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        tf.logging.set_verbosity(tf.logging.ERROR)
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

        try:
            if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
                self.logger.setLevel(os.environ['LOG_LEVEL'])
        except Exception as e:
            self.logger.error(
                'Unable to set logging level because: {0}, defaulting to INFO.'.format(str(e)))

        # Get "SKIP_RABBIT" environment variable with a default value of false
        self.skip_rabbit = os.getenv('SKIP_RABBIT', 'False')

        # Convert our string into a boolean
        self.skip_rabbit = self.skip_rabbit.lower() in ['true', 't', 'y', '1']
        self.logger.debug('SKIP_RABBIT set to: %s', str(self.skip_rabbit))

        self.get_config()
        self.connect_redis()

    def connect_redis(self, host='redis', port=6379, db=0):
        self.r = None
        try:
            self.r = StrictRedis(host=host, port=port, db=db,
                                 socket_connect_timeout=2)
        except Exception as e:
            self.logger.error(
                "Failed connect to Redis because: {0}".format(str(e)))
        return

    def connect_rabbit(self):
        # Rabbit settings
        self.exchange = 'topic-poseidon-internal'
        self.exchange_type = 'topic'

        # Starting rabbit connection
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='rabbit')
        )

        self.channel = self.connection.channel()
        self.channel.exchange_declare(
            exchange=self.exchange, exchange_type=self.exchange_type
        )

        self.routing_key = 'poseidon.algos.decider'
        self.logger.debug('Routing key: ' + self.routing_key)
        self.logger.debug('Exchange: ' + self.exchange)

        return

    def lookup_key(self, key):
        '''
        Look up a key from the input filename
        '''
        try:
            key_info = self.r.hgetall(key)
            endpoint = key_info[b'endpoint_data']
            endpoint = endpoint.decode('utf-8')
            end_dict = ast.literal_eval(endpoint)
            address = end_dict['ip-address']
        except Exception as e:
            self.logger.error("Failed to retrieve address because: {0}".format(str(e)))
            address = None
            return address, e

        return address, None

    def get_address_info(self, address, timestamp):
        '''
        Look up address information prior to the timestamp
        '''
        # Get the timestamps of the past updates for this address
        try:
            updates = self.r.hgetall(address)
            timestamps = json.loads(updates[b'timestamps'].decode('ascii'))
        except Exception as e:
            timestamps = None

        # If there is a previous update, read out the state
        last_update = None
        if timestamps is not None:
            # Get the most recent update prior to the current timestsmp
            updates = [time for time in timestamps if time < timestamp]
            if len(updates) > 0:
                last_update = max(updates)

        return last_update

    def get_previous_state(self, source_mac, timestamp):
        '''
        Gets the average representation vector from the most recent update
        before the current timestamp

        Args:
            source_mac: MAC address to read the representation from
            timestamp: Current timestamp.  Get only representations before this

        Returns:
            last_update: Timestamp of last update
            previous_representation: Average representation at last update
        '''

        # Try to read the old updates, if there are none return Nones
        try:
            updates = self.r.hgetall(source_mac)
        except Exception as e:
            return None, None

        # Get the most recent prior timestamp from the update list
        try:
            update_list = json.loads(updates[b'timestamps'].decode('ascii'))
        except Exception as e:
            self.logger.debug("Empty update list because: {0}".format(str(e)))
            update_list = []
        last_update = None
        for update in update_list:
            if update < timestamp.timestamp():
                last_update = update

        # Return Nones if there is no earlier update
        if last_update is None:
            return None, None

        # Read the last updated entry to get the previous representation
        key = source_mac + '_' + str(last_update)
        try:
            state = self.r.hgetall(key)
        except Exception as e:
            return None, None
        previous_representation = json.loads(
            state[b'representation'].decode('ascii')
        )
        return last_update, previous_representation

    def average_representation(
        self,
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
            if prev_time is None:
                representation = rep
                prev_time = time
            # If the time of the representation is after the previous update,
            # compute the exponentially weighted moving average.
            elif time > prev_time:
                time_diff = time - prev_time
                alpha = 1 - np.exp(-time_diff/self.time_const)
                representation += alpha*(rep - representation)
                prev_time = time

        return time, representation


    def update_data(
        self,
        source_mac,
        representations,
        timestamps,
        predictions,
        other_ips,
        model_hash
    ):
        '''
        Updates the stored data with the new information

        Args:
            source_mac: Address of the representaion to update
            representations: New observations of representations
            timestamps: Time at which each representation was observed
            predictions: Model predictions along with confidences
            other_ips: Other IP addresses the source has communicated with
            model_hash: Hash of the model used to compute this information
        '''
        # Get the previous update time and average representation
        last_update, prev_rep = self.get_previous_state(
            source_mac, timestamps[0])

        # Compute current representation
        time, current_rep = self.average_representation(
            representations, timestamps)

        # Compute moving average representation
        time, avg_rep = self.average_representation(
            representations,
            timestamps,
            prev_representation=prev_rep,
            last_update=last_update
        )

        # Separate labels and confidences
        labels = [label for label, confidence in predictions]
        confidences = [confidence for label, confidence in predictions]

        # Create the information to store
        key = source_mac + '_' + str(time)
        state = {
            'representation': list(avg_rep),
            'current_representation': list(current_rep),
            'labels': labels,
            'confidences': confidences,
            'other_ips': sorted(other_ips),
            'model_hash': model_hash
        }

        self.logger.debug('created key %s', key)
        self.logger.debug(state)
        try:
            self.logger.debug('Storing data')
            self.r.hmset(key, state)
            self.r.sadd('mac_addresses', source_mac)
            self.logger.debug('Storing update time')
            # Add this update time to the list of updates
            updates = self.r.hgetall(source_mac)
            update_list = json.loads(updates[b'timestamps'].decode('ascii'))
            self.logger.debug('Got previous updates from %s', source_mac)
        except Exception as e:
            self.logger.debug('No previous updates found for %s', source_mac)
            update_list = []

        update_list.append(time)
        update_list = sorted(update_list)
        times = {'timestamps': update_list}
        self.logger.debug('Updating %s', source_mac)
        self.logger.debug(times)
        try:
            self.r.hmset(source_mac, times)
            self.r.sadd('mac_addresses', source_mac)
        except Exception as e:
            self.logger.debug('Could not store update time')

        return current_rep, avg_rep, key

    def basic_decision(
        self,
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
            confs = [1, 0, 0]
            valid = False

        if key is None:
            key = address
            valid = False

        investigate = False
        if prev_time is not None and timestamp - prev_time > self.look_time:
            investigate = True
        if labels[0] == 'Unknown':
            investigate = True

        behavior = 'normal'
        if abnormality > self.threshold:
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

    def get_config(self):
        # Get time constant from config
        try:
            with open('opts/config.json') as config_file:
                config = json.load(config_file)
                self.time_const = config['time constant']
                self.state_size = config['state size']
                self.look_time = config['look time']
                self.threshold = config['threshold']
                self.conf_labels = config['labels']
                self.rnn_size = config['rnn size']
                #self.duration = config['duration']
                #self.batch_size = config['batch size']
        except Exception as e:  # pragma: no cover
            self.logger.error(
                "unable to read 'opts/config.json' properly because: %s", str(e))
        return

    def main(self):
        # path to the pcap to get the update from
        if len(sys.argv) < 2:
            pcap_path = '/pcaps/eval.pcap'
        else:
            pcap_path = sys.argv[1]

        source_mac = None
        key_address = None
        key = None
        split_path = "None"
        try:
            split_path = os.path.split(pcap_path)[-1]
            split_path = split_path.split('.')
            split_path = split_path[0].split('-')
            key = split_path[0].split('_')[1]
            key_address, _ = self.lookup_key(key)
        except Exception as e:
            self.logger.debug('Could not get address info because %s', str(e))

        # ignore misc files
        if (split_path[-1] != 'miscellaneous'):
            # Initialize and load the model
            if len(sys.argv) > 2:
                load_path = sys.argv[2]
            else:
                load_path = '/models/OneLayerModel.pkl'

            # Compute model hash
            with open(load_path, 'rb') as handle:
                model_hash = hashlib.md5(handle.read()).hexdigest()

            model = OneLayerModel(duration=None, hidden_size=None)
            model.load(load_path)
            self.logger.debug('Loaded model from %s', load_path)

            # Get representations from the model
            reps, source_mac, timestamps, preds, others = model.get_representation(
                pcap_path,
                source_ip=source_mac,
                mean=False
            )
            if preds is not None:
                self.logger.debug('Generating predictions')
                last_update, prev_rep = self.get_previous_state(
                    source_mac, timestamps[0])

                _, mean_rep = self.average_representation(
                    reps,
                    timestamps,
                    prev_representation=prev_rep,
                    last_update=last_update
                )
                mean_preds = model.classify_representation(mean_rep)
                if len(sys.argv) > 2:
                    for p in mean_preds:
                        self.logger.debug(p)
                # Update the stored representation
                avg_rep = None
                if reps is not None:
                    self.logger.debug('Updating stored data')
                    current_rep, avg_rep, r_key = self.update_data(
                        source_mac,
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
                inferred_mac = None
                for session_dict in sessions:
                    cleaned_sessions, inferred_mac = \
                        clean_session_dict(
                            session_dict,
                            source_address=source_mac
                        )
                    clean_sessions.append(cleaned_sessions)

                if source_mac is None:
                    source_mac = inferred_mac

                # Make simple decisions based on vector differences and update times
                timestamp = timestamps[0].timestamp()
                labels, confs = zip(*preds)
                if os.environ.get('POSEIDON_PUBLIC_SESSIONS'):
                    self.logger.debug('Bypassing abnormality detection')
                    abnormality = 0
                else:
                    abnormality = eval_pcap(
                        pcap_path, self.conf_labels, self.time_const, label=labels[0], rnn_size=self.rnn_size)
                prev_s = self.get_address_info(
                    source_mac,
                    timestamp
                )
                decision = self.basic_decision(
                    key,
                    source_mac,
                    prev_s,
                    timestamp,
                    labels,
                    confs,
                    abnormality
                )
                self.logger.debug('Created message')
                for i in range(3):
                    self.logger.info(labels[i] + ' : ' + str(round(confs[i], 3)))

                # update Redis with decision
                try:
                    self.r.hmset(r_key, decision)
                except Exception as e:
                    self.logger.error(
                        'Failed to update keys in Redis because: {0}'.format(str(e)))

                # Get json message
                message = json.dumps(decision)
                self.logger.info('Message: ' + message)
                if not self.skip_rabbit:
                    self.connect_rabbit()
                    self.channel.basic_publish(exchange=self.exchange,
                                               routing_key=self.routing_key,
                                               body=message)
            else:
                message = {}
                message[key] = {'valid': False}
                message = json.dumps(message)
                self.logger.info('Not enough sessions in pcap')
                if not self.skip_rabbit:
                    self.connect_rabbit()
                    self.channel.basic_publish(exchange=self.exchange,
                                               routing_key=self.routing_key,
                                               body=message)

        if not self.skip_rabbit:
            try:
                self.connection.close()
            except Exception as e:
                self.logger.error("Unable to close rabbit connection because: {0}".format(str(e)))
        return

if __name__ == '__main__':
    instance = OneLayerEval()
    instance.main()
