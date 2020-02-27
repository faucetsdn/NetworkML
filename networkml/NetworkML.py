from networkml.algorithms.host_footprint import HostFootprint
from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.parsers.pcap_to_csv import PCAPToCSV

import argparse
import datetime
import json
import logging
import os
import time

import humanize
import networkml
import pika


class NetworkML():


    def __init__(self, raw_args=None):
        self.logger = logging.getLogger(__name__)
        self.main(raw_args=raw_args)


    @staticmethod
    def connect_rabbit(host='messenger', port=5672, queue='task_queue'):
        params = pika.ConnectionParameters(host=host, port=port)
        connection = pika.BlockingConnection(params)
        channel = connection.channel()
        channel.queue_declare(queue=queue, durable=True)
        return channel


    @staticmethod
    def send_rabbit_msg(msg, channel, exchange='', routing_key='task_queue'):
        channel.basic_publish(exchange=exchange,
                              routing_key=routing_key,
                              body=json.dumps(msg),
                              properties=pika.BasicProperties(delivery_mode=2))
        print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                     str(msg['id']), str(msg['file_path'])))


    @staticmethod
    def parse_args(raw_args=None):
        parser = argparse.ArgumentParser()
        parser.add_argument('path', help='path to a single pcap file, or a directory of pcaps to parse')
        parser.add_argument('--algorithm', '-a', choices=['host_footprint'], default='host_footprint', help='choose which algorithm to use (default=host_footprint)')
        parser.add_argument('--engine', '-e', choices=['pyshark', 'tshark', 'host'], default='tshark', help='engine to use to process the PCAP file (default=tshark)')
        parser.add_argument('--first_stage', '-f', choices=['parser', 'featurizer', 'algorithm'], default='parser', help='choose which stage to start at, `path` arg is relative to stage (default=parser)')
        parser.add_argument('--final_stage', choices=['parser', 'featurizer', 'algorithm'], default='algorithm', help='choose which stage to finish at (default=algorithm)')
        parser.add_argument('--groups', '-g', default='tshark', help='groups of comma separated features to use (default=tshark)')
        parser.add_argument('--gzip', '-z', choices=['input', 'output', 'both'], default='both', help='use gzip between stages, useful when not using all 3 stages (default=both)')
        parser.add_argument('--level', '-l', choices=['packet', 'flow', 'host'], default='packet', help='level to make the output records (default=packet)')
        parser.add_argument('--operation', '-O', choices=['train', 'predict'], default='predict', help='choose which operation task to perform, train or predict (default=predict)')
        parser.add_argument('--output', '-o', default=None, help='directory to write out any results files to')
        parser.add_argument('--rabbit', '-r', action='store_true', help='Send prediction message to RabbitMQ')
        parser.add_argument('--threads', '-t', default=1, type=int, help='number of async threads to use (default=1)')
        parser.add_argument('--verbose', '-v', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        parsed_args = parser.parse_args(raw_args)
        return parsed_args


    def run_stages(self):
        invalid_stage_combo = False
        if self.first_stage == 'parser':
            instance = PCAPToCSV(raw_args=[self.in_path, '-e', self.engine, '-l', self.level, '-o', self.output, '-t', str(self.threads), '-v', self.log_level])
            result = instance.main()
            if self.final_stage != 'parser':
                instance = CSVToFeatures(raw_args=[result, '-c', '-g', self.groups, '-z', self.gzip_opt, '-o', self.output, '-t', str(self.threads), '-v', self.log_level])
                result = instance.main()
                if self.final_stage == 'algorithm':
                    instance = HostFootprint(raw_args=[result, '-O', self.operation, '-v', self.log_level])
                    result = instance.main()
        elif self.first_stage == 'featurizer':
            if self.final_stage == 'parser':
                invalid_stage_combo = True
            else:
                instance = CSVToFeatures(raw_args=[self.in_path, '-c', '-g', self.groups, '-z', self.gzip_opt, '-o', self.output, '-t', str(self.threads), '-v', self.log_level])
                result = instance.main()
                if self.final_stage == 'algorithm':
                    instance = HostFootprint(raw_args=[result, '-O', self.operation, '-v', self.log_level])
                    result = instance.main()
        elif self.first_stage == 'algorithm':
            if self.final_stage == 'algorithm':
                instance = HostFootprint(raw_args=[self.in_path, '-O', self.operation, '-v', self.log_level])
                result = instance.main()
            else:
                invalid_stage_combo = True
        else:
            invalid_stage_combo = True

        if invalid_stage_combo:
            self.logger.error('Invalid first and final stage combination')

        if self.final_stage == 'algorithm' and self.operation == 'predict':
            self.logger.info(f'Prediction: {result}')
            if self.rabbit:
                uid = os.getenv('id', 'None')
                file_path = os.getenv('file_path', 'None')
                try:
                    channel = NetworkML.connect_rabbit()
                    body = {'id': uid, 'type': 'metadata', 'file_path': file_path, 'data': result, 'results': {'tool': 'networkml', 'version': networkml.__version__}}
                    NetworkML.send_rabbit_msg(body, channel)
                    body = {'id': uid, 'type': 'metadata', 'file_path': file_path, 'data': '', 'results': {'tool': 'networkml', 'version': networkml.__version__}}
                except Exception as e:  # pragma: no cover
                    self.logger.error(f'Failed to send Rabbit message because: {e}')


    def main(self, raw_args=None):
        parsed_args = NetworkML.parse_args(raw_args=raw_args)
        self.in_path = parsed_args.path
        self.algorithm = parsed_args.algorithm
        self.engine = parsed_args.engine
        self.first_stage = parsed_args.first_stage
        self.final_stage = parsed_args.final_stage
        self.groups = parsed_args.groups
        self.gzip_opt = parsed_args.gzip
        self.level = parsed_args.level
        self.operation = parsed_args.operation
        self.output = parsed_args.output
        self.rabbit = parsed_args.rabbit
        self.threads = parsed_args.threads
        self.log_level = parsed_args.verbose

        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[self.log_level])

        self.run_stages()


if __name__ == "__main__":
    start = time.time()
    NetworkML()
    end = time.time()
    elapsed = end - start
    human_elapsed = humanize.naturaldelta(datetime.timedelta(seconds=elapsed))
    logging.info(f'Elapsed Time: {elapsed} seconds ({human_elapsed})')
