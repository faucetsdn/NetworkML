import argparse
import ast
import concurrent.futures
import csv
import datetime
import logging
import ntpath
import os
import pathlib
import random
import string
import sys
import time

from copy import deepcopy

import humanize
import pyshark

logging.basicConfig(level=logging.INFO)
PROTOCOLS = ['<IP Layer>',
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

def get_pyshark_data(pcap_file):
    all_protocols = set()

    dict_fp = '/tmp/networkml.' + ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
    with open(dict_fp, 'w') as f:
        with pyshark.FileCapture(pcap_file,
                                 use_json=True,
                                 include_raw=True,
                                 keep_packets=False,
                                 custom_parameters=['-o', 'tcp.desegment_tcp_streams:false', '-n']) as cap:
            for packet in cap:
                packet_dict = {}
                frame_info = packet.frame_info._all_fields
                for key in frame_info:
                    packet_dict[key] = frame_info[key]
                packet_dict['raw_packet'] = packet.get_raw_packet()
                layers = str(packet.layers)
                packet_dict['layers'] = layers
                str_layers = layers[1:-1].split(', ')
                for str_layer in str_layers:
                    # ignore raw layers
                    if 'RAW' not in str_layer:
                        all_protocols.add(str_layer)
                    # only include specified protocols due to unknown parsing for some layers
                    if str_layer in PROTOCOLS:
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

    for protocol in PROTOCOLS:
        if protocol in all_protocols:
            all_protocols.remove(protocol)
    pcap_file_short = ntpath.basename(pcap_file)
    if all_protocols:
        logger.warning(f'Found the following other layers in {pcap_file_short} that were not added to the CSV: {all_protocols}')

    return dict_fp

def get_csv_header(dict_fp):
    header_all = set()
    with open(dict_fp, 'r') as f:
        for line in f:
            header_all.update(ast.literal_eval(line.strip()).keys())
    header = []
    for key in header_all:
        if key[0].isalpha():
            header.append(key)
    return header

def write_dict_to_csv(dict_fp, out_file):
    header = get_csv_header(dict_fp)
    with open(out_file, 'w') as f:
        w = csv.DictWriter(f, header)
        w.writeheader()
        with open(dict_fp, 'r') as f:
            for line in f:
                w.writerow(ast.literal_eval(line.strip()))

def combine_csvs(out_paths, combined_path):
    # First determine the field names from the top line of each input file
    fieldnames = []
    for filename in out_paths:
        with open(filename, "r", newline="") as f_in:
            reader = csv.reader(f_in)
            headers = next(reader)
            for h in headers:
                if h not in fieldnames:
                    fieldnames.append(h)

    # Then copy the data
    with open(combined_path, "w", newline="") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        for filename in out_paths:
            with open(filename, "r", newline="") as f_in:
                reader = csv.DictReader(f_in)
                for line in reader:
                    writer.writerow(line)

def cleanup_files(paths):
    for fi in paths:
        if os.path.exists(fi):
            os.remove(fi)

def parse_file(in_file, out_file):
    dict_fp = get_pyshark_data(in_file)
    write_dict_to_csv(dict_fp, out_file)
    cleanup_files([dict_fp])

def process_files(threads, in_paths, out_paths):
    num_files = len(in_paths)
    finished_files = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as executor:
        future_to_parse = {executor.submit(parse_file, in_paths[i], out_paths[i]): i for i in range(len((in_paths)))}
        for future in concurrent.futures.as_completed(future_to_parse):
            path = future_to_parse[future]
            try:
                finished_files += 1
                future.result()
            except Exception as exc:
                logger.error(f'{path} generated an exception: {exc}')
            else:
                logger.info(f'Finished {finished_files}/{num_files} PCAPs.')

def ispcap(pathfile):
    for ext in ('pcap', 'pcapng', 'dump', 'capture'):
        if pathfile.endswith(''.join(('.', ext))):
            return True
    return False

def parse_args(parser):
    parser.add_argument('path', help='path to a single pcap file, or a directory of pcaps to parse')
    parser.add_argument('--combined', action='store_true', help='write out all records from all pcaps into a single csv file')
    parser.add_argument('--output', default=None, help='path to write out csv file or directory for csv files')
    parser.add_argument('--threads', default=1, type=int, help='number of async threads to use (default=1)')
    parsed_args = parser.parse_args()
    return parsed_args

def main():
    parsed_args = parse_args(argparse.ArgumentParser())
    in_path = parsed_args.path
    out_path = parsed_args.output
    combined = parsed_args.combined
    threads = parsed_args.threads
    in_paths = []
    out_paths = []

    # check if it's a directory or a file
    if os.path.isdir(in_path):
        if out_path:
            pathlib.Path(out_path).mkdir(parents=True, exist_ok=True)
        for root, _, files in os.walk(in_path):
            for pathfile in files:
                if ispcap(pathfile):
                    in_paths.append(os.path.join(root, pathfile))
                    if out_path:
                        out_paths.append(os.path.join(out_path, pathfile) + ".csv")
                    else:
                        out_paths.append(os.path.join(root, pathfile) + ".csv")
    else:
        in_paths.append(in_path)
        if out_path:
            out_paths.append(out_path)
        else:
            out_paths.append(in_path + ".csv")

    logger.info(f'Including the following layers in CSV: {PROTOCOLS}')
    process_files(threads, in_paths, out_paths)
    if combined:
        combined_path = os.path.join(os.path.dirname(out_paths[0]), "combined.csv")
        logger.info(f'Combining CSVs into a single file: {combined_path}')
        combine_csvs(out_paths, combined_path)
        cleanup_files(out_paths)
    else:
        logger.info(f'CSV file(s) written out to: {out_paths}')

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    start = time.time()
    main()
    end = time.time()
    elapsed = end - start
    human_elapsed = humanize.naturaldelta(datetime.timedelta(seconds=elapsed))
    logging.info(f'Elapsed Time: {elapsed} seconds ({human_elapsed})')
