import argparse
import concurrent.futures
import csv
import functools
import json
import logging
import ntpath
import os
import pathlib
import shlex
import subprocess
import tempfile
from copy import deepcopy

import pyshark

from networkml.helpers.gzipio import gzip_reader
from networkml.helpers.gzipio import gzip_writer


class PCAPToCSV():

    def __init__(self, raw_args=None):
        self.logger = logging.getLogger(__name__)
        self.PROTOCOLS = ['<IP Layer>',
                          '<ETH Layer>',
                          '<TCP Layer>',
                          '<UDP Layer>',
                          '<ICMP Layer>',
                          '<ICMPV6 Layer>',
                          '<DNS Layer>',
                          '<DHCP Layer>',
                          '<DHCPv6 Layer>',
                          '<ARP Layer>',
                          '<IPV6 Layer>',
                          '<TLS Layer>']
        self.raw_args = raw_args

    @staticmethod
    def ispcap(pathfile):
        for ext in ('pcap', 'pcapng', 'dump', 'capture'):
            if pathfile.endswith(''.join(('.', ext))):
                return True
        return False

    @staticmethod
    def parse_args(raw_args=None):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            'path', help='path to a single pcap file, or a directory of pcaps to parse')
        parser.add_argument('--combined', '-c', action='store_true',
                            help='write out all records from all pcaps into a single gzipped csv file')
        parser.add_argument('--engine', '-e', choices=['pyshark', 'tshark', 'host'],
                            default='tshark', help='engine to use to process the PCAP file (default=tshark)')
        parser.add_argument('--level', '-l', choices=['packet', 'flow', 'host'],
                            default='packet', help='level to make the output records (default=packet)')
        parser.add_argument('--output', '-o', default=None,
                            help='path to write out gzipped csv file or directory for gzipped csv files')
        parser.add_argument('--threads', '-t', default=1, type=int,
                            help='number of async threads to use (default=1)')
        parser.add_argument('--verbose', '-v', choices=[
                            'DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        parsed_args = parser.parse_args(raw_args)
        return parsed_args

    @staticmethod
    def get_csv_header(dict_fp):
        header_all = set()
        with gzip_reader(dict_fp) as f_in:
            for line in f_in:
                header_all.update(json.loads(line.strip()).keys())
        header = []
        for key in header_all:
            if key[0].isalpha() or key[0] == '_':
                header.append(key)
        return header

    @staticmethod
    def combine_csvs(out_paths, combined_path):
        # First determine the field names from the top line of each input file
        fieldnames = {'filename'}
        for filename in out_paths:
            with gzip_reader(filename) as f_in:
                reader = csv.reader(f_in)
                fieldnames.update({header for header in next(reader)})

        # Then copy the data
        with gzip_writer(combined_path) as f_out:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            for filename in out_paths:
                with gzip_reader(filename) as f_in:
                    reader = csv.DictReader(f_in)
                    for line in reader:
                        line['filename'] = filename.split(
                            '/')[-1].split('csv.gz')[0]
                        writer.writerow(line)
                    PCAPToCSV.cleanup_files([filename])

    @staticmethod
    def cleanup_files(paths):
        for fi in paths:
            if os.path.exists(fi):
                os.remove(fi)

    def get_pyshark_packet_data(self, pcap_file, dict_fp):
        all_protocols = set()

        pcap_file_short = ntpath.basename(pcap_file)
        with gzip_writer(dict_fp) as f_out:
            with pyshark.FileCapture(pcap_file,
                                     use_json=True,
                                     include_raw=True,
                                     keep_packets=False,
                                     custom_parameters=['-o', 'tcp.desegment_tcp_streams:false', '-n']) as cap:
                for packet in cap:
                    packet_dict = {}
                    packet_dict['filename'] = pcap_file_short
                    frame_info = packet.frame_info._all_fields
                    for key in frame_info:
                        packet_dict[key] = frame_info[key]
                    # can overflow the field size for csv
                    #packet_dict['raw_packet'] = packet.get_raw_packet()
                    layers = str(packet.layers)
                    packet_dict['layers'] = layers
                    str_layers = layers[1:-1].split(', ')
                    for str_layer in str_layers:
                        # ignore raw layers
                        if 'RAW' not in str_layer:
                            all_protocols.add(str_layer)
                        # only include specified protocols due to unknown parsing for some layers
                        if str_layer in self.PROTOCOLS:
                            layer_info = getattr(packet, str_layer.split()[
                                                 0][1:].lower())._all_fields
                            # check for nested dicts, one level deep
                            for key in layer_info:
                                # DNS doesn't parse well
                                if isinstance(layer_info[key], dict) and str_layer != '<DNS Layer>':
                                    for inner_key in layer_info[key]:
                                        packet_dict[inner_key] = layer_info[key][inner_key]
                                else:
                                    packet_dict[key] = layer_info[key]
                    # clean up records
                    packet_dict_copy = deepcopy(packet_dict)
                    keys = packet_dict_copy.keys()
                    for key in keys:
                        if not key[0].isalpha() or key == 'tcp.payload_raw' or key == 'tcp.payload':
                            del packet_dict[key]
                    f_out.write(json.dumps(packet_dict) + '\n')

        for protocol in self.PROTOCOLS:
            if protocol in all_protocols:
                all_protocols.remove(protocol)
        if all_protocols:
            self.logger.warning(
                f'Found the following other layers in {pcap_file_short} that were not added to the CSV: {all_protocols}')

    def get_tshark_conv_data(self, pcap_file, dict_fp):
        # TODO (add a summary of other packets with protocols?)
        output = ''
        try:
            # TODO perhaps more than just tcp/udp in the future
            options = '-n -q -z conv,tcp -z conv,udp'
            output = subprocess.check_output(shlex.split(
                ' '.join(['tshark', '-r', pcap_file, options])))
            output = output.decode('utf-8')
        except Exception as e:  # pragma: no cover
            self.logger.error(f'{e}')

        in_block = False
        name = None
        results = {}
        for line in output.split('\n'):
            if line.startswith('==='):
                if in_block:
                    in_block = False
                    name = None
                    continue
                else:
                    in_block = True
                    continue
            if in_block:
                if not name:
                    name = ''.join(line.split(':')).strip()
                    results[name] = ''
                    continue
                elif not line.startswith('Filter:') and line != '':
                    results[name] += line + '\n'

        with gzip_writer(dict_fp) as f_out:
            for result in results.keys():
                if 'Conversations' in result:
                    transport_proto = result.split()[0]
                    # handle conversation parsing
                    for line in results[result].split('\n'):
                        if line == '' or line.startswith(' '):
                            # header or padding, dicard
                            continue
                        else:
                            # TODO perhaps additional features can be extracted for flows from tshark
                            src, _, dst, frames_l, bytes_l, frames_r, bytes_r, frames_total, bytes_total, rel_start, duration = line.split()
                            conv = {'Source': src.rsplit(':', 1)[0],
                                    'Source Port': src.rsplit(':', 1)[1],
                                    'Destination': dst.rsplit(':', 1)[0],
                                    'Destination Port': dst.rsplit(':', 1)[1],
                                    'Transport Protocol': transport_proto,
                                    'Frames to Source': frames_l,
                                    'Bytes to Source': bytes_l,
                                    'Frames to Destination': frames_r,
                                    'Bytes to Destination': bytes_r,
                                    'Total Frames': frames_total,
                                    'Total Bytes': bytes_total,
                                    'Relative Start': rel_start,
                                    'Duration': duration}
                            f_out.write(json.dumps(conv) + '\n')

    @staticmethod
    @functools.lru_cache()
    def good_json_key(key):
        return (key[0].isalpha() or key[0] == '_') and ';' not in key and '(' not in key and '\\' not in key and '{' not in key and '<' not in key and '+' not in key

    def flatten_json(self, item):
        flattened_dict = {}

        def flatten(key, value):
            if isinstance(value, list):
                for i, sub_item in enumerate(value):
                    flatten(str(i), sub_item)
            elif isinstance(value, dict):
                sub_keys = value.keys()
                for sub_key in sub_keys:
                    flatten(sub_key, value[sub_key])
            else:
                # remove junk
                if self.good_json_key(key):
                    # limit field size for csv
                    if (value and len(value) < 131072) or not value:
                        flattened_dict[key] = value

        flatten('', item)
        return flattened_dict

    def json_packet_records(self, process):
        json_buffer = []

        def _recordize():
            return json.loads('\n'.join(json_buffer))

        depth = 0
        while True:
            json_line = process.stdout.readline().decode(encoding='utf-8', errors='ignore')
            if json_line == '' and process.poll() is not None:
                break
            if not json_line.startswith(' '):
                continue
            json_line = json_line.strip()
            bracket_line = json_line.rstrip(',')
            if bracket_line.endswith('}'):
                depth -= 1
            elif bracket_line.endswith('{'):
                depth += 1
            if depth == 0:
                if bracket_line:
                    json_buffer.append(bracket_line)
                if json_buffer:
                    yield _recordize()
                json_buffer = []
            else:
                if json_line:
                    json_buffer.append(json_line)

    def get_tshark_packet_data(self, pcap_file, dict_fp):
        options = '-n -V -Tjson'
        try:
            process = subprocess.Popen(shlex.split(
                ' '.join(['tshark', '-r', pcap_file, options])), stdout=subprocess.PIPE)
            with gzip_writer(dict_fp) as f_out:
                for item in self.json_packet_records(process):
                    f_out.write(json.dumps(self.flatten_json(item)) + '\n')
        except Exception as e:  # pragma: no cover
            self.logger.error(f'{e}')

    def get_tshark_host_data(self, pcap_file, dict_fp):
        # TODO
        raise NotImplementedError('To be implemented')

    def write_dict_to_csv(self, dict_fp, out_file):
        header = PCAPToCSV.get_csv_header(dict_fp)
        with gzip_writer(out_file) as f_out:
            writer = csv.DictWriter(f_out, fieldnames=header)
            writer.writeheader()
            try:
                with gzip_reader(dict_fp) as f_in:
                    for line in f_in:
                        writer.writerow(json.loads(line.strip()))
            except Exception as e:  # pragma: no cover
                self.logger.error(f'Failed to write to CSV because: {e}')

    def parse_file(self, level, in_file, out_file, engine):
        self.logger.info(f'Processing {in_file}')
        with tempfile.TemporaryDirectory() as tmpdir:
            dict_fp = os.path.join(tmpdir, os.path.basename(in_file))
            if level == 'packet':
                if engine == 'tshark':
                    # option for tshark as it's much faster
                    self.get_tshark_packet_data(in_file, dict_fp)
                elif engine == 'pyshark':
                    # using pyshark to get everything possible
                    self.get_pyshark_packet_data(in_file, dict_fp)
            elif level == 'flow':
                # using tshark conv,tcp and conv,udp filters
                self.get_tshark_conv_data(in_file, dict_fp)
            elif level == 'host':
                # TODO unknown what should be in this, just the overarching stats?
                raise NotImplementedError('To be implemented')
            self.write_dict_to_csv(dict_fp, out_file)
            PCAPToCSV.cleanup_files([dict_fp])

    def process_files(self, threads, level, in_paths, out_paths, engine):
        num_files = len(in_paths)
        failed_paths = []
        finished_files = 0
        # corner case so it works in jupyterlab
        if threads < 2:
            for i in range(len(in_paths)):
                try:
                    finished_files += 1
                    self.parse_file(level, in_paths[i], out_paths[i], engine)
                    self.logger.info(
                        f'Finished {in_paths[i]}. {finished_files}/{num_files} PCAPs done.')
                except Exception as e:  # pragma: no cover
                    self.logger.error(
                        f'{in_paths[i]} generated an exception: {e}')
                    failed_paths.append(out_paths[i])
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as executor:
                future_to_parse = {executor.submit(
                    self.parse_file, level, in_paths[i], out_paths[i], engine): i for i in range(len(in_paths))}
                for future in concurrent.futures.as_completed(future_to_parse):
                    path = future_to_parse[future]
                    try:
                        finished_files += 1
                        future.result()
                    except Exception as e:  # pragma: no cover
                        self.logger.error(
                            f'{in_paths[path]} generated an exception: {e}')
                        failed_paths.append(out_paths[path])
                    else:
                        self.logger.info(
                            f'Finished {in_paths[path]}. {finished_files}/{num_files} PCAPs done.')
        return failed_paths

    def main(self):
        parsed_args = PCAPToCSV.parse_args(raw_args=self.raw_args)
        in_path = parsed_args.path
        out_path = parsed_args.output
        combined = parsed_args.combined
        engine = parsed_args.engine
        threads = parsed_args.threads
        log_level = parsed_args.verbose
        level = parsed_args.level

        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])

        in_paths = []
        out_paths = []

        # check if it's a directory or a file
        if os.path.isdir(in_path):
            if out_path:
                pathlib.Path(out_path).mkdir(parents=True, exist_ok=True)
            for root, _, files in os.walk(in_path):
                for pathfile in files:
                    if PCAPToCSV.ispcap(pathfile):
                        in_paths.append(os.path.join(root, pathfile))
                        if out_path:
                            out_paths.append(os.path.join(
                                out_path, pathfile) + '.csv.gz')
                        else:
                            out_paths.append(os.path.join(
                                root, pathfile) + '.csv.gz')
        else:
            in_paths.append(in_path)
            default_out_path = in_path + '.csv.gz'

            if out_path:
                if os.path.isdir(out_path):
                    out_paths.append(os.path.join(out_path, os.path.basename(default_out_path)))
                else:
                    out_paths.append(out_path)
            else:
                out_paths.append(default_out_path)

        if level == 'packet' and engine == 'pyshark':
            self.logger.info(
                f'Including the following layers in CSV (if they exist): {self.PROTOCOLS}')

        failed_paths = self.process_files(
            threads, level, in_paths, out_paths, engine)

        for failed_path in failed_paths:  # pragma: no cover
            if failed_path in out_paths:
                out_paths.remove(failed_path)

        if combined:
            if out_paths:
                combined_path = os.path.join(
                    os.path.dirname(out_paths[0]), 'combined.csv.gz')
            else:
                combined_path = 'combined.csv.gz'
            self.logger.info(
                f'Combining CSVs into a single file: {combined_path}')
            PCAPToCSV.combine_csvs(out_paths, combined_path)
            return combined_path
        else:
            self.logger.info(
                f'GZipped CSV file(s) written out to: {out_paths}')
            if len(out_paths) > 1:
                return os.path.dirname(out_paths[0])
            return out_paths[0]


if __name__ == '__main__':  # pragma: no cover
    instance = PCAPToCSV()
    instance.main()
