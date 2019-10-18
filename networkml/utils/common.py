import ast ## Abstract syntax tree - this module helps in parsing code
import logging
import os

import numpy as np
import pika
from redis import StrictRedis


class Common:
    """
    Common functions that are shared across models
    """

    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        self.r = None
        self.logger = self.setup_logger(self.logger)
        self.setup_env()

        if config:
            try:
                self.time_const = config['time constant']
                self.state_size = config['state size']
                self.look_time = config['look time']
                self.threshold = config['threshold']
                self.rnn_size = config['rnn size']
                self.conf_labels = config['conf labels']
            except Exception as e:  # pragma: no cover
                self.logger.error(
                    'Unable to read config properly because: %s', str(e))

    @staticmethod
    def setup_logger(logger):
        try:
            if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
                logger.setLevel(os.environ['LOG_LEVEL'])
        except Exception as e:  # pragma: no cover
            logger.error(
                'Unable to set logging level because: {0}, defaulting to INFO.'.format(str(e)))
        return logger

    def setup_env(self):
        # Get "RABBIT" environment variable with a default value of false
        self.use_rabbit = os.getenv('RABBIT', 'False')
        self.rabbit_host = os.getenv('RABBIT_HOST', 'rabbit')
        self.rabbit_port = int(os.getenv('RABBIT_PORT', '5672'))
        self.rabbit_exchange = os.getenv(
            'RABBIT_EXCHANGE', 'topic-poseidon-internal')
        self.rabbit_routing_key = os.getenv(
            'RABBIT_ROUTING_KEY', 'poseidon.algos.decider')
        self.rabbit_queue = os.getenv('RABBIT_QUEUE', 'False')
        self.rabbit_queue = self.rabbit_queue.lower() in [
            'true', 't', 'y', '1']
        self.rabbit_queue_name = os.getenv('RABBIT_QUEUE_NAME', '')

        # Get "REDIS" environment variable with a default value of false
        self.use_redis = os.getenv('REDIS', 'False')
        self.redis_host = 'redis'
        if 'REDIS_HOST' in os.environ and os.environ['REDIS_HOST'] != '':
            self.redis_host = os.environ['REDIS_HOST']

        # Convert our string into a boolean
        self.use_rabbit = self.use_rabbit.lower() in ['true', 't', 'y', '1']
        self.logger.debug('RABBIT flag set to: %s', str(self.use_rabbit))
        self.use_redis = self.use_redis.lower() in ['true', 't', 'y', '1']
        self.logger.debug('REDIS flag set to: %s', str(self.use_redis))
        return

    def connect_redis(self, host='redis', port=6379, db=0):
        self.r = None
        try:
            self.r = StrictRedis(host=host, port=port, db=db,
                                 socket_connect_timeout=2)
        except Exception as e:  # pragma: no cover
            self.logger.error(
                'Failed connect to Redis because: {0}'.format(str(e)))
        return

    def connect_rabbit(self,
                       host='rabbit',
                       port=5672,
                       exchange='topic-poseidon-internal',
                       exchange_type='topic',
                       routing_key='poseidon.algos.decider',
                       queue=False,
                       queue_name=''):
        # Rabbit settings
        self.connection = None
        self.exchange = exchange
        self.exchange_type = exchange_type

        try:
            # Starting rabbit connection
            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=host, port=port)
            )
        except Exception as e:  # pragma: no cover
            self.logger.error(
                'Failed to open RabbitMQ connection because: {0}'.format(str(e)))
            return

        self.channel = self.connection.channel()
        if queue:
            self.channel.queue_declare(queue=queue_name, durable=True)
        else:
            self.channel.exchange_declare(
                exchange=self.exchange, exchange_type=self.exchange_type
            )

        self.routing_key = routing_key
        self.logger.debug('Routing key: ' + self.routing_key)
        self.logger.debug('Exchange: ' + self.exchange)

        return

    def get_address_info(self, address, timestamp):
        '''
        Look up address information prior to the timestamp
        '''
        # Get the timestamps of the past updates for this address
        if self.use_redis:
            try:
                updates = self.r.hgetall(address)
                timestamps = ast.literal_eval(
                    updates[b'timestamps'].decode('ascii'))
            except Exception as e:  # pragma: no cover
                self.logger.debug(
                    'No timestamp found because: {0}, setting to None'.format(str(e)))
                timestamps = None
        else:
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
        if self.use_redis:
            try:
                updates = self.r.hgetall(source_mac)
            except Exception as e:  # pragma: no cover
                self.logger.warning(
                    'Unable to read old updates because: {0}, defaulting to None'.format(str(e)))
                return None, None
        else:
            return None, None

        # Get the most recent prior timestamp from the update list
        try:
            update_list = ast.literal_eval(
                updates[b'timestamps'].decode('ascii'))
        except Exception as e:  # pragma: no cover
            self.logger.debug(
                'Empty update list because: {0} key not found'.format(str(e)))
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
        previous_representation = None
        try:
            state = self.r.hgetall(key)
            previous_representation = ast.literal_eval(
                state[b'representation'].decode('ascii'))
        except Exception as e:  # pragma: no cover
            self.logger.error(
                'Failed to get previous representation because: {0}'.format(str(e)))
            return None, None
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
        if self.use_redis:
            redis_state = {}
            for k in state:
                redis_state[k] = str(state[k])
            try:
                self.logger.debug('Storing data')
                self.r.hmset(key, redis_state)
                self.r.sadd('mac_addresses', source_mac)
                self.logger.debug('Storing update time')
                # Add this update time to the list of updates
                updates = self.r.hgetall(source_mac)
                update_list = ast.literal_eval(
                    updates[b'timestamps'].decode('ascii'))
                self.logger.debug(
                    'Got previous updates from {0}'.format(source_mac))
            except Exception as e:  # pragma: no cover
                self.logger.debug(
                    'No previous updates found for {0} because: {1}'.format(source_mac, str(e)))
                update_list = []

            update_list.append(time)
            update_list = sorted(update_list)
            times = {'timestamps': update_list}
            self.logger.debug('Updating %s', source_mac)
            self.logger.debug(times)
            redis_times = {}
            for k in times:
                redis_times[k] = str(times[k])
            try:
                self.r.hmset(source_mac, redis_times)
                self.r.sadd('mac_addresses', source_mac)
            except (ConnectionError, TimeoutError) as e:  # pragma: no cover
                self.logger.debug(
                    'Could not store update time because: %s', str(e))

        return key

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
