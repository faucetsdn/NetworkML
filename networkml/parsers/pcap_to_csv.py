import argparse
import ast
import concurrent.futures
import csv
import datetime
import gzip
import io
import json
import logging
import ntpath
import os
import pathlib
import random
import shlex
import string
import subprocess
import time

from copy import deepcopy

import humanize
import pyshark


class PCAPToCSV():


    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.PROTOCOLS = ['<IP Layer>',
                          '<ETH Layer>',
                          '<TCP Layer>',
                          '<UDP Layer>',
                          '<ICMP Layer>',
                          '<ICMPv6 Layer>',
                          '<DNS Layer>',
                          '<DHCP Layer>',
                          '<DHCPv6 Layer>',
                          '<ARP Layer>',
                          '<IP6 Layer>',
                          '<TLS Layer>']
        self.flattened_dict = {}


    @staticmethod
    def ispcap(pathfile):
        for ext in ('pcap', 'pcapng', 'dump', 'capture'):
            if pathfile.endswith(''.join(('.', ext))):
                return True
        return False


    @staticmethod
    def parse_args(parser):
        parser.add_argument('path', help='path to a single pcap file, or a directory of pcaps to parse')
        parser.add_argument('--combined', '-c', action='store_true', help='write out all records from all pcaps into a single gzipped csv file')
        parser.add_argument('--engine', '-e', choices=['pyshark', 'tshark', 'host'], default='tshark', help='engine to use to process the PCAP file (default=tshark)')
        parser.add_argument('--level', '-v', choices=['packet', 'flow', 'host'], default='packet', help='level to make the output records (default=packet)')
        parser.add_argument('--logging', '-l', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        parser.add_argument('--output', '-o', default=None, help='path to write out gzipped csv file or directory for gzipped csv files')
        parser.add_argument('--threads', '-t', default=1, type=int, help='number of async threads to use (default=1)')
        parsed_args = parser.parse_args()
        return parsed_args


    @staticmethod
    def get_csv_header(dict_fp):
        header_all = set()
        with gzip.open(dict_fp, 'rb') as f:
            for line in io.TextIOWrapper(f, newline=''):
                header_all.update(ast.literal_eval(line.strip()).keys())
        header = []
        for key in header_all:
            if key[0].isalpha() or key[0] == '_':
                header.append(key)
        return header


    @staticmethod
    def combine_csvs(out_paths, combined_path):
        # First determine the field names from the top line of each input file
        fieldnames = []
        for filename in out_paths:
            with gzip.open(filename, 'rb') as f_in:
                reader = csv.reader(io.TextIOWrapper(f_in, newline=''))
                headers = next(reader)
                for h in headers:
                    if h not in fieldnames:
                        fieldnames.append(h)

        fieldnames.append('filename')
        # Then copy the data
        with gzip.open(combined_path, 'wb') as f_out:
            writer = csv.DictWriter(io.TextIOWrapper(f_out, newline='', write_through=True), fieldnames=fieldnames)
            writer.writeheader()
            for filename in out_paths:
                with gzip.open(filename, 'rb') as f_in:
                    reader = csv.DictReader(io.TextIOWrapper(f_in, newline=''))
                    for line in reader:
                        line['filename'] = filename.split('/')[-1].split('csv.gz')[0]
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
        with gzip.open(dict_fp, 'w') as f:
            f = io.TextIOWrapper(f, newline='', write_through=True)
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
                            layer_info = getattr(packet, str_layer.split()[0][1:].lower())._all_fields
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
                        if not key[0].isalpha():
                            del packet_dict[key]
                    print(packet_dict, file=f)

        for protocol in self.PROTOCOLS:
            if protocol in all_protocols:
                all_protocols.remove(protocol)
        if all_protocols:
            self.logger.warning(f'Found the following other layers in {pcap_file_short} that were not added to the CSV: {all_protocols}')


    def get_tshark_conv_data(self, pcap_file, dict_fp):
        # TODO (add a summary of other packets with protocols?)
        output = ''
        try:
            # TODO perhaps more than just tcp/udp in the future
            options = '-n -q -z conv,tcp -z conv,udp'
            output = subprocess.check_output(shlex.split(' '.join(['tshark', '-r', pcap_file, options])))
            output = output.decode("utf-8")
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

        with gzip.open(dict_fp, 'w') as f:
            f = io.TextIOWrapper(f, newline='', write_through=True)
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
                            print(conv, file=f)


    def flatten_json(self, key, value):
        if isinstance(value, list):
            i=0
            for sub_item in value:
                self.flatten_json(str(i), sub_item)
                i=i+1
        elif isinstance(value, dict):
            sub_keys = value.keys()
            for sub_key in sub_keys:
                self.flatten_json(sub_key, value[sub_key])
        else:
            # remove junk
            if (key[0].isalpha() or key[0] == '_') and ';' not in key and '(' not in key and '\\' not in key and '{' not in key and '<' not in key and '+' not in key:
                # limit field size for csv
                if (value and len(value) < 131072) or not value:
                    self.flattened_dict[key] = value


    def get_tshark_packet_data(self, pcap_file, dict_fp):
        output = b'[]'
        try:
            options = '-n -V -Tjson'
            output = subprocess.check_output(shlex.split(' '.join(['tshark', '-r', pcap_file, options])))
        except Exception as e:  # pragma: no cover
            self.logger.error(f'{e}')
        output = json.loads(output.decode("utf-8", "ignore"))

        with gzip.open(dict_fp, 'w') as f:
            f = io.TextIOWrapper(f, newline='', write_through=True)
            for item in output:
                self.flattened_dict = {}
                self.flatten_json('', item)
                print(self.flattened_dict, file=f)


    def get_tshark_host_data(self, pcap_file, dict_fp):
        # TODO
        raise NotImplementedError("To be implemented")


    def write_dict_to_csv(self, dict_fp, out_file):
        header = PCAPToCSV.get_csv_header(dict_fp)
        with gzip.open(out_file, 'wb') as f:
            w = csv.DictWriter(io.TextIOWrapper(f, newline='', write_through=True), fieldnames=header)
            w.writeheader()
            try:
                with gzip.open(dict_fp, 'rb') as f:
                    for line in io.TextIOWrapper(f, newline=''):
                        w.writerow(ast.literal_eval(line.strip()))
            except Exception as e:
                self.logger.error(f'Failed to write to CSV because: {e}')


    def parse_file(self, level, in_file, out_file, engine):
        self.logger.info(f'Processing {in_file}')
        dict_fp = '/tmp/networkml.' + ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
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
            raise NotImplementedError("To be implemented")
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
                    self.logger.info(f'Finished {in_paths[i]}. {finished_files}/{num_files} PCAPs done.')
                except Exception as e:
                    self.logger.error(f'{in_paths[i]} generated an exception: {e}')
                    failed_paths.append(out_paths[i])
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as executor:
                future_to_parse = {executor.submit(self.parse_file, level, in_paths[i], out_paths[i], engine): i for i in range(len(in_paths))}
                for future in concurrent.futures.as_completed(future_to_parse):
                    path = future_to_parse[future]
                    try:
                        finished_files += 1
                        future.result()
                    except Exception as exc:
                        self.logger.error(f'{in_paths[path]} generated an exception: {exc}')
                        failed_paths.append(out_paths[path])
                    else:
                        self.logger.info(f'Finished {in_paths[path]}. {finished_files}/{num_files} PCAPs done.')
        return failed_paths


    def main(self):
        parsed_args = PCAPToCSV.parse_args(argparse.ArgumentParser())
        in_path = parsed_args.path
        out_path = parsed_args.output
        combined = parsed_args.combined
        engine = parsed_args.engine
        threads = parsed_args.threads
        log_level = parsed_args.logging
        level = parsed_args.level

        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
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
                            out_paths.append(os.path.join(out_path, pathfile) + ".csv.gz")
                        else:
                            out_paths.append(os.path.join(root, pathfile) + ".csv.gz")
        else:
            in_paths.append(in_path)
            if out_path:
                out_paths.append(out_path)
            else:
                out_paths.append(in_path + ".csv.gz")

        if level == 'packet' and engine == 'pyshark':
            self.logger.info(f'Including the following layers in CSV (if they exist): {self.PROTOCOLS}')

        failed_paths = self.process_files(threads, level, in_paths, out_paths, engine)

        for failed_path in failed_paths:
            if failed_path in out_paths:
                out_paths.remove(failed_path)

        if combined:
            combined_path = os.path.join(os.path.dirname(out_paths[0]), "combined.csv.gz")
            self.logger.info(f'Combining CSVs into a single file: {combined_path}')
            PCAPToCSV.combine_csvs(out_paths, combined_path)
        else:
            self.logger.info(f'GZipped CSV file(s) written out to: {out_paths}')


if __name__ == '__main__':  # pragma: no cover
    start = time.time()
    instance = PCAPToCSV()
    instance.main()
    end = time.time()
    elapsed = end - start
    human_elapsed = humanize.naturaldelta(datetime.timedelta(seconds=elapsed))
    logging.info(f'Elapsed Time: {elapsed} seconds ({human_elapsed})')
