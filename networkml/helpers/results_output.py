import json
import os
import re
import socket

import pika

import networkml


class ResultsOutput:

    def __init__(self, logger, version, use_rabbit):
        self.logger = logger
        self.version = version
        self.use_rabbit = use_rabbit
        self.rabbit_host = os.getenv('RABBIT_HOST', 'messenger')
        self.rabbit_queue_name = os.getenv('RABBIT_QUEUE_NAME', 'task_queue')
        self.rabbit_exchange = os.getenv('RABBIT_EXCHANGE', 'task_queue')
        self.rabbit_port = int(os.getenv('RABBIT_PORT', '5672'))
        self.rabbit_routing_key = os.getenv('RABBIT_ROUTING_KEY', 'task_queue')

    def connect_rabbit(self):
        params = pika.ConnectionParameters(host=self.rabbit_host, port=self.rabbit_port)
        connection = pika.BlockingConnection(params)
        channel = connection.channel()
        channel.queue_declare(queue=self.rabbit_queue_name, durable=True)
        return (connection, channel)

    def send_rabbit_msg(self, msg, channel):
        body = json.dumps(msg)
        channel.basic_publish(exchange=self.rabbit_exchange,
                              routing_key=self.rabbit_routing_key,
                              body=body,
                              properties=pika.BasicProperties(delivery_mode=2))
        self.logger.info('send_rabbit_msg: %s', body)

    def rabbit_msg_template(self, uid, file_path, result):
        return {
            'id': uid,
            'type': 'metadata',
            'file_path': file_path,
            'data': result,
            'results': {
                'tool': 'networkml',
                'version': self.version}}

    @staticmethod
    def assign_labels(labels):
        netml_path = list(networkml.__path__)
        la = os.path.join(netml_path[0],
                          'trained_models/label_assignments.json')
        assignment_map = {}
        with open(la) as f:
            assignment_map = json.load(f)
        labels = [assignment_map[label] if label in assignment_map else label for label in labels]
        return labels

    @staticmethod
    def parse_pcap_name(base_pcap):
        # The parsing operation below assumes a specific file naming
        # convention trace_DeviceName-deviceID-time-duration-flags.pcap
        # Explanation: All files coming from Poseidon have trace_ at their
        # beginning. The device name and deviceID colums are self explanatory.
        # Time refers to the day of the week and time of day. Duration refers
        # to the length of the network traffic capture. The flags aspect
        # refers to an unknown characteristic.
        # TODO: tolerate tshark labels in the trace name, but do not parse them for now.
        pcap_key = None
        pcap_labels = None
        if base_pcap.startswith('trace_'):
            for pcap_re, key_pos, label_pos in (
                    (re.compile(
                        r'^trace_([\da-f]+)_([0-9\_\-]+)-(client|server)-(.+).pcap$'), 1, 4),
                    (re.compile(r'^trace_([\da-f]+)_([0-9\_\-]+).pcap$'), 1, None)):
                pcap_match = pcap_re.match(base_pcap)
                if pcap_match:
                    pcap_key = pcap_match.group(key_pos)
                    if label_pos:
                        pcap_labels = pcap_match.group(label_pos)
                    break
        else:
            # Not a Poseidon trace file, return basename as key.
            pcap_key = base_pcap.split('.')[0]
        return (pcap_key, pcap_labels)

    def results_template(self, file_path, valid, results):
        base_pcap = os.path.basename(file_path)
        pcap_key, pcap_labels = self.parse_pcap_name(base_pcap)
        base_results = {'valid': valid, 'pcap_labels': pcap_labels}
        base_results.update(results)
        return {pcap_key: base_results, 'pcap': base_pcap}

    def output_msg(self, uid, file_path, result):
        if not self.use_rabbit:
            return

        msg = result
        try:
            msg = self.rabbit_msg_template(uid, file_path, result)
            (connection, channel) = self.connect_rabbit()
            self.send_rabbit_msg(msg, channel)
            msg = self.rabbit_msg_template(uid, file_path, '')
            self.send_rabbit_msg(msg, channel)
            connection.close()
        except (socket.gaierror, pika.exceptions.AMQPConnectionError) as err:
            self.logger.error(f'Failed to send Rabbit message {msg} because: {err}')

    def output_invalid(self, uid, file_path, filename):
        self.output_msg(
            uid, file_path, self.results_template(filename, False, {}))

    @staticmethod
    def valid_template(timestamp, source_ip, source_mac,
                       behavior, investigate, labels, confidences):
        return {
            'decisions': {
                'behavior': behavior,
                'investigate': investigate,
            },
            'classification': {
                'labels': labels,
                'confidences': confidences,
            },
            'timestamp': timestamp,
            'source_ip': source_ip,
            'source_mac': source_mac,
        }

    def output_valid(self, uid, file_path, filename, timestamp, source_ip, source_mac,
                     labels, confidences, behavior='normal',
                     investigate=False):
        labels = self.assign_labels(labels)
        self.output_msg(uid, file_path, self.results_template(
            filename, True, self.valid_template(
                timestamp, source_ip, source_mac,
                behavior, investigate, labels, confidences)))

    def output_from_result_json(self, uid, file_path, result_json):
        result = json.loads(result_json)
        for filename, host_results in result.items():
            filename = filename.split('.csv.gz')[0]
            for host_result in host_results:
                top_role = host_result.get('top_role', None)
                if top_role is None:
                    self.output_invalid(uid, file_path, filename)
                    continue
                investigate = top_role == 'Unknown'
                source_ip = host_result.get('source_ip', None)
                source_mac = host_result.get('source_mac', None)
                timestamp = host_result.get('timestamp', None)
                labels, confidences = zip(*host_result['role_list'])
                self.output_valid(
                    uid, file_path, filename, timestamp, source_ip, source_mac,
                    labels, confidences, investigate=investigate)
