import json
import logging
import os
import re
import time

import pika
from cpuinfo import get_cpu_info

import networkml
from networkml.parsers.pcap.pcap_utils import clean_session_dict
from networkml.utils.common import Common
from networkml.utils.model import Model
from networkml.utils.training_utils import get_labels
from networkml.utils.training_utils import get_pcap_paths
from networkml.utils.training_utils import get_true_label


class BaseAlgorithm:
    """
    Base algorithm class that reads a PCAP (packet capture file) and updates the
    stored representation of the source. The class can then be used by more
    specific algorithms.
    """

    def __init__(self, files=None, config=None, model=None, model_hash=None,
                 model_path=None, sos_model=None):

        ## Initiate logging information on this instance
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        logging.getLogger('pika').setLevel(logging.WARNING)
        self.logger = Common().setup_logger(self.logger)
        self.common = Common(config=config)
        self.sos_model = sos_model

        ## RabbitMQ acts as a message broker
        if self.common.use_rabbit:
            self.common.connect_rabbit(host=self.common.rabbit_host,
                                       port=self.common.rabbit_port,
                                       exchange=self.common.rabbit_exchange,
                                       routing_key=self.common.rabbit_routing_key,
                                       queue=self.common.rabbit_queue,
                                       queue_name=self.common.rabbit_queue_name)

        ## Redis provides a storage capability
        if self.common.use_redis:
            self.common.connect_redis(host=self.common.redis_host)

        if config:
            try:
                ## For description of these configuration values, see the
                ## README.md file in the networkml/configs folder
                self.time_const = config['time constant']
                self.state_size = config['state size']
                self.look_time = config['look time']
                self.threshold = config['threshold']
                self.rnn_size = config['rnn size']
                self.conf_labels = config['conf labels']
                self.duration = config['duration']
            except Exception as e:  # pragma: no cover
                self.logger.error(
                    'Unable to read config properly because: %s', str(e))

        self.files = files if files else [] ## Store network capture files
        self.model = model
        self.model_hash = model_hash
        self.model_path = model_path
        self.has_avx = self.detect_avx

    @staticmethod
    def detect_avx():
        ## Check if CPU supports AVX (advanced vector extension),
        ## which speeds up certain calculations
        if 'flags' in get_cpu_info() and (
                'avx' in get_cpu_info()['flags'] or 'avx2' in get_cpu_info()['flags']):
            return True
        return False

    @staticmethod
    def parse_pcap_name(base_pcap):
        ## The parsing operation below assumes a specific file naming
        ## convention trace_DeviceName-deviceID-time-duration-flags.pcap
        ## Explanation: All files coming from Poseidon have trace_ at their
        ## beginning. The device name and deviceID colums are self explanatory.
        ## Time refers to the day of the week and time of day. Duration refers
        ## to the length of the network traffic capture. The flags aspect
        ## refers to an unknown characteristic.
        # TODO: tolerate tshark labels in the trace name, but do not parse them for now.
        pcap_key = None
        pcap_labels = None
        if base_pcap.startswith('trace_'):
            pcap_re = re.compile(r'^trace_([\da-f]+)_.+(client|server)-(.+).pcap$')
            pcap_match = pcap_re.match(base_pcap)
            if pcap_match:
                pcap_key = pcap_match.group(1)
                pcap_labels = pcap_match.group(3)
        else:
            # Not a Poseidon trace file, return basename as key.
            pcap_key = base_pcap.split('.')[0]
        return (pcap_key, pcap_labels)

    @staticmethod
    def parse_pcap_labels(pcap_labels_str):
        pcap_labels = {
            'ip_lowest_port': None,
            'ip_proto': None,
            'ip_version': None,
            'ip_app': None,
        }
        pcap_label_res = {
            'ip_lowest_port': re.compile(r'.*port-(\d+).*'),
            'ip_proto': re.compile(r'.+\-(arp|icmp|icmp6|udp|tcp)\-.+'),
            'ip_app': re.compile(r'.+\-(bootp|dns|esp|ftp|http|ssl|ntp)\-.+'),
        }
        for field, label_re in pcap_label_res.items():
            match = label_re.match(pcap_labels_str)
            if match:
                pcap_labels[field] = match.group(1)
        if 'ipv6' in pcap_labels_str:
            pcap_labels['ip_version'] = 6
        elif pcap_labels['ip_proto'] is not None:
            pcap_labels['ip_version'] = 4
        return pcap_labels

    def publish_message(self, message, close=False):
        if self.common.use_rabbit:
            uid = os.getenv('id', 'None')
            file_path = os.getenv('file_path', 'None')
            message.update({
                'id': uid,
                'file_path': file_path,
                'type': 'metadata',
                'results': {'tool': 'networkml', 'version': networkml.__version__}})
            message = json.dumps(message)
            self.logger.info('Message: ' + message)
            self.common.channel.basic_publish(
                exchange=self.common.exchange,
                routing_key=self.common.routing_key,
                body=message,
                properties=pika.BasicProperties(delivery_mode=2,))
            if close:
                try:
                    self.common.connection.close()
                except Exception as e:  # pragma: no cover
                    self.logger.error(
                        'Unable to close rabbit connection because: {0}'.format(str(e)))

    def eval(self, algorithm):
        """
        This operation uses a specified algorithm to predict--for particular
        network traffic--what devices types are present and whether the device
        is acting normally or abnormally. This is the function that should be
        used in production when a user wants to actually employ networkML to
        classify and assess traffic.

        Args:
            algorithm: type of algorithm (random forest, neural network, or
            stochastic outlier selection (SOS).
        """
        if self.files:
            self.model.sessionize_pcaps(self.files)

        for fi in self.files:
            self.logger.info('Processing {0}...'.format(fi))
            base_pcap = os.path.basename(fi)
            pcap_key, pcap_labels = self.parse_pcap_name(base_pcap)
            if pcap_key is None:
                self.logger.debug('Ignoring unknown pcap name %s', base_pcap)
                continue

            ## Get representations from the model
            reps, source_mac, timestamps, preds, others, capture_ip_source = self.model.get_representation(
                str(fi),
                source_ip=None,
                mean=False
            )

            ## If no predictions are made, send a message with explanation
            if preds is None:
                message = {}
                message[pcap_key] = {'valid': False, 'pcap': base_pcap}
                message = {'data': message}
                self.logger.info(
                    'Not enough sessions in file \'%s\'', str(fi))
                self.publish_message(message)
                continue

            else: ## If a prediction is made, send message with prediction
                self.logger.debug('Generating predictions')

                ## Update the stored representation
                if reps is not None:
                    self.logger.debug('Updating stored data')
                    r_key = self.common.update_data(
                        source_mac,
                        reps,
                        timestamps,
                        preds,
                        others,
                        self.model_hash
                    )

                ## Get the sessions that the model looked at
                sessions = self.model.sessions
                ## Clean the sessions
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

                ## Make simple decisions based on vector differences and update
                ## times
                timestamp = timestamps[0].timestamp()
                labels, confs = zip(*preds)
                abnormality = 0.0
                if self.has_avx():
                    from networkml.algorithms.sos.eval_SoSModel import eval_pcap
                    try:
                        abnormality = eval_pcap(
                            str(fi), self.sos_model, self.conf_labels, self.time_const, label=labels[0],
                            rnn_size=self.rnn_size, model_path=self.model_path, model_type=algorithm)
                    except ValueError:
                        self.logger.warning("Can't run abnormality detection because not a big enough sample size")
                else:
                    self.logger.warning(
                        "Can't run abnormality detection because this CPU doesn't support AVX")

                prev_s = self.common.get_address_info(
                    source_mac,
                    timestamp
                )
                decision = self.common.basic_decision(
                    pcap_key,
                    source_mac,
                    prev_s,
                    timestamp,
                    labels,
                    confs,
                    abnormality
                )
                sources = {
                    'source_ip': capture_ip_source,
                    'source_mac': source_mac,
                    'pcap_labels': pcap_labels,
                }
                if pcap_key in decision:
                    decision[pcap_key].update(sources)
                elif source_mac in decision:
                    decision[source_mac].update(sources)
                self.logger.debug('Created message')
                for i in range(3):
                    self.logger.info(
                        labels[i] + ' : ' + str(round(confs[i], 3)))

                # update Redis with decision
                if self.common.use_redis:
                    redis_decision = {}
                    for k in decision:
                        redis_decision[k] = str(decision[k])
                    try:
                        self.common.r.hmset(r_key, redis_decision)
                    except Exception as e:  # pragma: no cover
                        self.logger.error(
                            'Failed to update keys in Redis because: {0}'.format(str(e)))

                message = {'data': decision}
                message['data']['pcap'] = base_pcap
                self.publish_message(message)

        message = {'data': ''}
        self.publish_message(message, close=True)

    def train(self, data_dir, save_path, m, algorithm):
        # Initialize the model
        model = Model(
            duration=self.duration,
            hidden_size=self.state_size,
            labels=self.conf_labels,
            model=m,
            model_type=algorithm,
            threshold_time=self.threshold
        )
        # Train the model
        model.train(data_dir)
        # Save the model to the specified path
        model.save(save_path)

    def test(self, data_dir, save_path):
        # Initialize results dictionary
        results = {}
        results['labels'] = self.conf_labels

        # Get the true label assignments
        self.logger.info('Getting label assignments')
        label_assignments = get_labels(
            'networkml/configs/label_assignments.json', model_labels=self.model.labels)

        if not label_assignments:
            self.logger.warn(
                'Could not read label assignments; continuing anyway.')

        # Walk through testing directory and get all the pcaps
        self.logger.info('Getting pcaps')
        pcaps = get_pcap_paths(data_dir)
        if not pcaps:
            self.logger.error(
                'No pcaps were found in data directory; exiting.')
            return

        # Evaluate the model on each pcap
        file_size = 0
        file_num = 0
        time_slices = 0
        self.logger.info('processing pcaps')
        tick = time.perf_counter()
        self.model.sessionize_pcaps(pcaps)
        for pcap in pcaps:
            # Get the true label
            name, label = get_true_label(pcap, label_assignments)
            single_result = {}
            single_result['label'] = label
            self.logger.info('Reading ' + name + ' as ' + label)
            # Get the internal representations
            representations, _, _, p, _, _ = self.model.get_representation(
                pcap, mean=False)
            if representations is not None:
                file_size += os.path.getsize(pcap)
                file_num += 1
                length = representations.shape[0]
                time_slices += length
                single_result['aggregate'] = p
                individual_dict = {}
                # Classify each slice
                self.logger.info('Computing classifications by slice')
                for i in range(length):
                    p_r = self.model.classify_representation(
                        representations[i])
                    individual_dict[i] = p_r
                single_result['individual'] = individual_dict
                results[pcap] = single_result
        tock = time.perf_counter()

        # Save results to path specified by third argument
        with open(save_path, 'w') as output_file:
            json.dump(results, output_file)
        self.logger.info('-'*80)
        self.logger.info('Results with unknowns')
        self.logger.info('-'*80)
        self.model.calc_f1(results)
        self.logger.info('-'*80)
        self.logger.info('Results forcing decisions')
        self.logger.info('-'*80)
        self.model.calc_f1(results, ignore_unknown=True)
        self.logger.info('-'*80)
        self.logger.info('Analysis statistics')
        self.logger.info('-'*80)
        elapsed_time = tock - tick
        rate = file_size/(pow(10, 6)*elapsed_time)
        self.logger.info('Evaluated {0} pcaps in {1} seconds'.format(
            file_num, round(elapsed_time, 3)))
        self.logger.info('Total data: {0} Mb'.format(file_size/pow(10, 6)))
        self.logger.info('Total capture time: {0} hours'.format(time_slices/4))
        self.logger.info(
            'Data processing rate: {0} Mb per second'.format(rate))
        self.logger.info('time per 15 minute capture {0} seconds'.format(
            (elapsed_time)/(time_slices+0.01)))
        self.logger.info('-'*80)
