import hashlib
import json
import logging
import os
import sys

from pathlib import Path

from networkml.algorithms.sos.eval_SoSModel import eval_pcap
from networkml.parsers.pcap.pcap_utils import clean_session_dict
from networkml.utils.common import Common
from networkml.utils.model import Model


class OneLayer:
    """
    Reads a pcap and updates the stored representation of the source using
    the one layer feedforward model.
    """

    def __init__(self, files=None, config=None, model=None):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

        self.logger = Common().setup_logger(self.logger)
        self.common = Common(config=config)
        if not self.common.skip_rabbit:
            self.common.connect_rabbit()
        self.r = self.common.r
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

        self.files = files if files else []
        self.model = model

    def eval(self):
        for fi in self.files:
            self.logger.info('Processing {0}...'.format(fi))
            source_mac = None
            key = None
            split_path = 'None'
            try:
                split_path = os.path.split(fi)[-1]
                split_path = split_path.split('.')
                split_path = split_path[0].split('-')
                key = split_path[0].split('_')[1]
            except Exception as e:
                self.logger.debug('Could not get key because %s', str(e))

            # ignore misc files
            if (split_path[-1] == 'miscellaneous'):
                continue

            # Get representations from the model
            reps, source_mac, timestamps, preds, others = self.model.get_representation(
                str(fi),
                source_ip=source_mac,
                mean=False
            )
            if preds is None:
                message = {}
                message[key] = {'valid': False}
                message = json.dumps(message)
                self.logger.info(
                    'Not enough sessions in file \'%s\'', str(fi))
                if not self.common.skip_rabbit:
                    self.common.channel.basic_publish(exchange=self.common.exchange,
                                                      routing_key=self.common.routing_key,
                                                      body=message)
                continue

            else:
                self.logger.debug('Generating predictions')
                last_update, prev_rep = self.common.get_previous_state(
                    source_mac, timestamps[0])

                _, mean_rep = self.common.average_representation(
                    reps,
                    timestamps,
                    prev_representation=prev_rep,
                    last_update=last_update
                )
                mean_preds = self.model.classify_representation(mean_rep)
                if len(sys.argv) > 2:
                    for p in mean_preds:
                        self.logger.debug(p)
                # Update the stored representation
                if reps is not None:
                    self.logger.debug('Updating stored data')
                    r_key = self.common.update_data(
                        source_mac,
                        reps,
                        timestamps,
                        preds,
                        others,
                        model_hash
                    )

                # Get the sessions that the model looked at
                sessions = self.model.sessions
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
                abnormality = 0
                abnormality = eval_pcap(
                    str(fi), self.conf_labels, self.time_const, label=labels[0],
                    rnn_size=self.rnn_size, model_path=load_path, model_type='OneLayer')
                prev_s = self.common.get_address_info(
                    source_mac,
                    timestamp
                )
                decision = self.common.basic_decision(
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
                    self.logger.info(
                        labels[i] + ' : ' + str(round(confs[i], 3)))

                # update Redis with decision
                redis_decision = {}
                for k in decision:
                    redis_decision[k] = str(decision[k])
                try:
                    self.r.hmset(r_key, redis_decision)
                except Exception as e:
                    self.logger.error(
                        'Failed to update keys in Redis because: {0}'.format(str(e)))

                # Get json message
                message = json.dumps(decision)
                self.logger.info('Message: ' + message)
                if not self.common.skip_rabbit:
                    self.common.channel.basic_publish(exchange=self.common.exchange,
                                                      routing_key=self.common.routing_key,
                                                      body=message)

        if not self.common.skip_rabbit:
            try:
                self.common.connection.close()
            except Exception as e:
                self.logger.error(
                    'Unable to close rabbit connection because: {0}'.format(str(e)))
        return

    def train(self):
        # Load model params from config
        config = get_config(args.config)
        duration = config['duration']
        hidden_size = config['state size']
        labels = config['labels']

        # Get the data directory
        data_dir = args.pcaps

        m = MLPClassifier(
            (hidden_size),
            alpha=0.1,
            activation='relu',
            max_iter=1000
        )

        # Initialize the model
        model = Model(
            duration=duration,
            hidden_size=hidden_size,
            labels=labels,
            model=m,
            model_type='OneLayer',
            threshold_time=self.threshold
        )
        # Train the model
        model.train(data_dir)
        # Save the model to the specified path
        model.save(args.save)

    def test(self):
        data_dir = args.pcaps
        save_path = args.save

        # Initialize results dictionary
        results = {}
        results['labels'] = model.labels

        # Get the true label assignments
        logger.info('Getting label assignments')
        label_assignments = utils.get_labels(
            args.labels, model_labels=model.labels)
        if not label_assignments:
            logger.warn('Could not read label assignments; continuing anyway.')

        # Walk through testing directory and get all the pcaps
        logger.info('Getting pcaps')
        pcaps = utils.get_pcap_paths(data_dir)
        if not pcaps:
            logger.error('No pcaps were found in data directory; exiting.')
            return

        # Evaluate the model on each pcap
        file_size = 0
        file_num = 0
        time_slices = 0
        logger.info('processing pcaps')
        tick = time.clock()
        for pcap in pcaps:
            # Get the true label
            name, label = utils.get_true_label(pcap, label_assignments)
            single_result = {}
            single_result['label'] = label
            logger.info('Reading ' + name + ' as ' + label)
            # Get the internal representations
            representations, _, _, p, _ = model.get_representation(
                pcap, mean=False)
            if representations is not None:
                file_size += os.path.getsize(pcap)
                file_num += 1
                length = representations.shape[0]
                time_slices += length
                single_result['aggregate'] = p
                individual_dict = {}
                # Classify each slice
                logger.info('Computing classifications by slice')
                for i in range(length):
                    p_r = model.classify_representation(representations[i])
                    individual_dict[i] = p_r
                single_result['individual'] = individual_dict
                results[pcap] = single_result
        tock = time.clock()

        # Save results to path specified by third argument
        with open(save_path, 'w') as output_file:
            json.dump(results, output_file)
        logger.info('-'*80)
        logger.info('Results with unknowns')
        logger.info('-'*80)
        model.calc_f1(results)
        logger.info('-'*80)
        logger.info('Results forcing decisions')
        logger.info('-'*80)
        model.calc_f1(results, ignore_unknown=True)
        logger.info('-'*80)
        logger.info('Analysis statistics')
        logger.info('-'*80)
        elapsed_time = tock - tick
        rate = file_size/(pow(10, 6)*elapsed_time)
        logger.info('Evaluated {0} pcaps in {1} seconds'.format(
            file_num, round(elapsed_time, 3)))
        logger.info('Total data: {0} Mb'.format(file_size/pow(10, 6)))
        logger.info('Total capture time: {0} hours'.format(time_slices/4))
        logger.info('Data processing rate: {0} Mb per second'.format(rate))
        logger.info('time per 15 minute capture {0} seconds'.format(
            (elapsed_time)/(time_slices)))
        logger.info('-'*80)
