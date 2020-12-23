import json
import os
import re

import networkml


class ResultsOutput:

    def __init__(self, logger, uid, file_path):
        self.logger = logger
        self.uid = uid
        self.file_path = file_path

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

    @staticmethod
    def valid_template(uid, file_path, timestamp, source_ip, investigate, labels, confidences,
                       pcap_labels, base_pcap, pcap_key):
        return {
            'uid': uid,
            'file_path': file_path,
            'pcap': base_pcap,
            'pcap_key': pcap_key,
            'pcap_labels': pcap_labels,
            'timestamp': timestamp,
            'source_ip': source_ip,
            'decisions': {
                'investigate': investigate,
            },
            'classification': {
                'labels': labels,
                'confidences': confidences,
            },
        }

    def output_from_result_json(self, result_json_str, reformatted_result_json_file_name):
        base_pcap = os.path.basename(self.file_path)
        pcap_key, pcap_labels = self.parse_pcap_name(base_pcap)
        result_json = json.loads(result_json_str)

        mac_metadata = {}
        for filename, host_results in result_json.items():
            filename = filename.split('.csv.gz')[0]
            for host_result in host_results:
                top_role = host_result.get('top_role', None)
                if top_role is not None:
                    investigate = top_role == 'Unknown'
                    source_ip = host_result.get('source_ip', None)
                    source_mac = host_result.get('source_mac', None)
                    timestamp = host_result.get('timestamp', None)
                    labels, confidences = zip(*host_result['role_list'])
                    labels = self.assign_labels(labels)
                    mac_metadata[source_mac] = self.valid_template(
                        self.uid, self.file_path, timestamp, source_ip,
                        investigate, labels, confidences,
                        pcap_labels, base_pcap, pcap_key)
        reformatted_json = {
            'tool': 'networkml',
            'data': {
                'mac_addresses': mac_metadata,
            }}
        with open(reformatted_result_json_file_name, 'w') as reformatted_result:
            reformatted_result.write(json.dumps(reformatted_json))
        return reformatted_json
