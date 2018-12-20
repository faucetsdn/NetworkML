import hashlib
import json
import logging
import os
import sys

from pathlib import Path
from poseidonml.common import Common
from poseidonml.eval_SoSModel import eval_pcap
from poseidonml.Model import Model
from poseidonml.pcap_utils import clean_session_dict


class OneLayerEval:
    """
    Reads a pcap and updates the stored representation of the source using
    the one layer feedforward model.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

        self.common = Common()
        self.logger = Common().setup_logger(self.logger)
        self.r = self.common.r
        self.time_const = self.common.time_const
        self.state_size = self.common.state_size
        self.look_time = self.common.look_time
        self.threshold = self.common.threshold
        self.conf_labels = self.common.conf_labels
        self.rnn_size = self.common.rnn_size
        self.skip_rabbit = self.common.skip_rabbit

    def main(self):
        # path to pcap or directory to get update from
        pcaps = []
        if len(sys.argv) < 2:
            pcap_path = '/pcaps/eval.pcap'
        else:
            pcap_path = sys.argv[1]

        if Path(pcap_path).is_dir():
            for child in Path(pcap_path).iterdir():
                if child.is_file() and \
                        os.path.split(str(child))[-1].split('.')[-1] in {'pcap', 'dump', 'cap'}:
                    pcaps.append(str(child))
        elif Path(pcap_path).is_file() and \
                os.path.split(str(pcap_path))[-1].split('.')[-1] in {'pcap', 'dump', 'cap'}:
            pcaps.append(str(pcap_path))
        else:
            self.logger.error(
                'Input \'%s\' was neither pcap nor directory.', str(pcap_path))
            return

        if not pcaps:
            self.logger.error(
                'Did not find pcap file(s) from \'%s\'.', str(pcap_path))
            return

        if not self.skip_rabbit:
            self.common.connect_rabbit()

        # Initialize and load the model
        if len(sys.argv) > 2:
            load_path = sys.argv[2]
        else:
            load_path = '/models/OneLayerModel.pkl'

        # Compute model hash
        with open(load_path, 'rb') as handle:
            model_hash = hashlib.md5(handle.read()).hexdigest()

        model = Model(duration=None, hidden_size=None,
                      model_type='OneLayer')
        model.load(load_path)
        self.logger.debug('Loaded model from %s', load_path)

        for pcap in pcaps:
            self.logger.info('Processing {0}...'.format(pcap))
            source_mac = None
            key = None
            split_path = 'None'
            try:
                split_path = os.path.split(pcap)[-1]
                split_path = split_path.split('.')
                split_path = split_path[0].split('-')
                key = split_path[0].split('_')[1]
            except Exception as e:
                self.logger.debug('Could not get key because %s', str(e))

            # ignore misc files
            if (split_path[-1] == 'miscellaneous'):
                continue

            # Get representations from the model
            reps, source_mac, timestamps, preds, others = model.get_representation(
                str(pcap),
                source_ip=source_mac,
                mean=False
            )
            if preds is None:
                message = {}
                message[key] = {'valid': False}
                message = json.dumps(message)
                self.logger.info(
                    'Not enough sessions in pcap \'%s\'', str(pcap))
                if not self.skip_rabbit:
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
                mean_preds = model.classify_representation(mean_rep)
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
                abnormality = 0
                abnormality = eval_pcap(
                    str(pcap), self.conf_labels, self.time_const, label=labels[0],
                    rnn_size=self.rnn_size, model_type='OneLayer')
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
                for key in decision:
                    redis_decision[key] = str(decision[key])
                try:
                    self.r.hmset(r_key, redis_decision)
                except Exception as e:
                    self.logger.error(
                        'Failed to update keys in Redis because: {0}'.format(str(e)))

                # Get json message
                message = json.dumps(decision)
                self.logger.info('Message: ' + message)
                if not self.skip_rabbit:
                    self.common.channel.basic_publish(exchange=self.common.exchange,
                                                      routing_key=self.common.routing_key,
                                                      body=message)

        if not self.skip_rabbit:
            try:
                self.common.connection.close()
            except Exception as e:
                self.logger.error(
                    'Unable to close rabbit connection because: {0}'.format(str(e)))
        return


if __name__ == '__main__':
    instance = OneLayerEval()
    instance.main()
