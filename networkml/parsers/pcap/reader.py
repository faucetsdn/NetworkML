import binascii
import csv
import io
import gzip
import datetime
import os
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor, as_completed
import pyshark

CSV_FIELDS = ('session_no', 'key', 'timestamp', 'packet')


def parse_packet_head(packet):
    '''
    Parses the head of the packet to get the key tuple which contains
    the flow level data

    Args:
        line: Header line from tcpdump

    Returns:
        key: Tuple key which contains packet info
    '''
    # TODO: should be using utcfromtimestamp()
    date = datetime.datetime.fromtimestamp(float(packet.frame_info.time_epoch))

    src_address = None
    dst_address = None
    for ip_type in ('ip', 'ipv6'):
        try:
            ip_fields = getattr(packet, ip_type)
        except AttributeError:
            continue
        src_address = getattr(ip_fields, '%s.src' % ip_type)
        dst_address = getattr(ip_fields, '%s.dst' % ip_type)

    src_port = '0'
    dst_port = '0'
    for ip_proto_type in ('tcp', 'udp'):
        try:
            ip_fields = getattr(packet, ip_proto_type)
        except AttributeError:
            continue
        src_port = getattr(ip_fields, '%s.srcport' % ip_proto_type)
        dst_port = getattr(ip_fields, '%s.dstport' % ip_proto_type)

    if src_address and dst_address:
        src_key = ':'.join((src_address, src_port))
        dst_key = ':'.join((dst_address, dst_port))
        return (
            (date, src_key, dst_key),
            {src_key: packet.highest_layer, dst_key: packet.highest_layer})

    return None


def packetizer(path):
    '''
    Reads a pcap specified by the path and parses out the packets.
    Packets will be stored with a tuple key formatted as follows:
    (datetime, sIP:sPort, dIP:dPort, protocol, length)

    Args:
        path: Path to pcap to read

    Returns:
        packet_dict: Dictionary of packets with keys formatted as above
    '''
    packet_dict = OrderedDict()
    highest_layers_dict = {}
    with pyshark.FileCapture(
            path, use_json=True, include_raw=True, keep_packets=False,
            custom_parameters=['-o', 'tcp.desegment_tcp_streams:false', '-n']) as cap:
        for packet in cap:
            head = parse_packet_head(packet)
            if head is None:
                continue
            raw_packet = packet.get_raw_packet()
            payload_offset = len(raw_packet)
            transport_payload_size = 0
            # Strip payload beyond transport layer, if any.
            if packet.transport_layer:
                transport_layer = packet[packet.transport_layer]
                if hasattr(transport_layer, 'payload_raw'):
                    transport_payload_size = int(transport_layer.payload_raw[2])
                elif hasattr(transport_layer, 'length_raw'):
                    transport_payload_size = int(transport_layer.length_raw[0], 16)
            payload_offset = min(len(raw_packet) - transport_payload_size, 128)
            keys, highest_layers = head
            stripped_data = raw_packet[:payload_offset]
            packet_dict[keys] = binascii.hexlify(stripped_data).decode('utf-8')
            for key, highest_layer in highest_layers.items():
                if key not in highest_layers_dict:
                    highest_layers_dict[key] = set()
                highest_layers_dict[key].update({highest_layer})
    return packet_dict, highest_layers_dict


def sessionizer(logger, path, duration=None, threshold_time=None):
    '''
    Reads a pcap specified by the path and parses out the sessions.
    Sessions are defined as flows with matching sourceIP:sourcePort
    and destinationIP:destinationPorts. The sessions can also be binned
    in time according to the optional duration parameter.

    Args:
        path: Path to pcap to read
        duration: Duration of session bins. None uses a single bin for
                  the entire pcap.

    Returns:
        session_dict: Dictionary of sessions with keys as tuples of
                      (sourceIP:sourcePort, destIP:destPort)
    '''

    logger.info(f'sessionizing {path}')
    # Get the packets from the pcap
    packet_dict, _ = packetizer(path)

    # Go through the packets one by one and add them to the session dict
    sessions = []
    start_time = None
    working_dict = None

    first_packet_time = None
    session_starts = OrderedDict()

    if not threshold_time or threshold_time < 1:
        cfg_threshold = None
        threshold_time = cfg_threshold if cfg_threshold and cfg_threshold > 0 else 120

    for head, packet in packet_dict.items():
        time = head[0]

        # Get the time of the first observed packet
        if first_packet_time is None:
            first_packet_time = time

        # Start off the first bin when the first packet is seen
        if start_time is None:
            start_time = time
            working_dict = OrderedDict()

        # If duration has been specified, check if a new bin should start
        if duration is not None:
            if (time-start_time).total_seconds() >= duration:
                sessions.append(working_dict)
                working_dict = OrderedDict()
                start_time = time

        # Add the key to the session dict if it doesn't exist
        key_1 = (head[1], head[2])
        key_2 = (head[2], head[1])

        # Select the appropriate ordering
        if key_2 in working_dict:
            key = key_2
        if key_1 in working_dict:
            key = key_1

        if key_1 not in working_dict and key_2 not in working_dict:
            if key_1 not in session_starts and key_2 not in session_starts:
                session_starts[key_1] = time

            if key_1 in session_starts:
                session_start = session_starts[key_1]
            if key_2 in session_starts:
                session_start = session_starts[key_2]

            key = key_1
            if (session_start - first_packet_time).total_seconds() > threshold_time:
                working_dict[key] = []

        # Add the session to the session dict if its start time is after the cutoff
        if key in working_dict:
            working_dict[key].append((head[0], packet))

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)
    return sessions


def csv_suffix():
    return '.'.join(('session', 'csv', 'gz'))


def pcap_filename_to_csv_filename(pcap_filename, out_dir):
    '''
    Convert pcap filename to CSV filename.

    Args:
        pcap_filename: full path to pcap file.
        out_dir: directory for new CSV file.
    Returns:
        name of CSV file.
    '''
    csv_base = os.path.basename(pcap_filename)
    csv_filename = os.path.join(out_dir, '.'.join((csv_base[:csv_base.rfind('.')], csv_suffix())))
    return csv_filename


def pcap_to_sessioncsv(out_dir, pcap_filename, pcap_sessions):
    '''
    Write session dicts to gzipped CSV file (opposite of pcap_to_sessioncsv()).

    Args:
        out_dir: directory to write CSV file in.
        pcap_filename: path to original pcap file.
        pcap_sessions: list of session dicts.
    '''
    csv_filename = pcap_filename_to_csv_filename(pcap_filename, out_dir)
    with gzip.open(csv_filename, 'wb') as csv_file:
        writer = csv.DictWriter(
            io.TextIOWrapper(csv_file, newline='', write_through=True), fieldnames=CSV_FIELDS)
        writer.writeheader()
        for session_no, pcap_session in enumerate(pcap_sessions):
            for key, session_data in pcap_session.items():
                for timestamp, packet in session_data:
                    writer.writerow({
                        'session_no': session_no,
                        'key': '-'.join(key),
                        'timestamp': timestamp.timestamp(),
                        'packet': packet})


def sessioncsv_to_sessions(csv_filename):
    '''
    Parse CSV file containing sessions (opposite of pcap_to_sessioncsv()).

    Args:
        csv_filename: full path to gzipped CSV.
    Returns:
        list of session dicts.
    '''
    sessions = []
    last_session_no = None
    with gzip.open(csv_filename) as csv_file:
        reader = csv.DictReader(io.TextIOWrapper(csv_file, newline=''))
        working_dict = OrderedDict()
        for row in reader:
            session_no = row['session_no']
            if last_session_no != session_no:
                if working_dict:
                    sessions.append(working_dict)
                    working_dict = OrderedDict()
                last_session_no = session_no
            key = tuple(row['key'].split('-'))
            if key not in working_dict:
                working_dict[key] = []
            working_dict[key].append(
                (datetime.datetime.fromtimestamp(float(row['timestamp'])), row['packet']))
    if working_dict:
        sessions.append(working_dict)
    return sessions


def parallel_sessionizer(logger, pcap_files, duration=None, threshold_time=None, csv_out_dir=None):
    '''
    Run sessionizer() in parallel across many pcap files.

    Args:
        logger: logger instance.
        pcap_files: list of files to process.
        duration and threshold_time: passed to sessionizer().
        csv_out_dir: where to cache CSVs of sessions (default is same dir as pcap).
    Returns:
        dict of session_dicts, keyed by pcap filename.
    '''
    # Process smaller files first - many small files can be processed in parallel.
    pcap_files = sorted(pcap_files, key=os.path.getsize, reverse=True)
    csv_filenames = {}
    for pcap_file in pcap_files:
        if csv_out_dir is not None:
            csv_dir = csv_out_dir
        else:
            csv_dir = os.path.dirname(pcap_file)
        csv_file = pcap_filename_to_csv_filename(pcap_file, csv_dir)
        csv_filenames[pcap_file] = csv_file

    with ProcessPoolExecutor() as executor:
        unparsed_pcaps = []
        pcap_file_sessions = {}
        # Retrieve pre-cached CSVs.
        for pcap_file in pcap_files:
            csv_file = csv_filenames[pcap_file]
            if os.path.exists(csv_file):
                logger.info(f'found cached sessions pulling up {csv_file}')
                pcap_file_sessions[pcap_file] = sessioncsv_to_sessions(csv_file)
            else:
                logger.info(f'no cache found, adding {pcap_file} to be sessionized')
                unparsed_pcaps.append(pcap_file)
        futures = {
            executor.submit(sessionizer, logger, pcap_file, duration, threshold_time): pcap_file
            for pcap_file in unparsed_pcaps}
        for future in as_completed(futures):
            pcap_file = futures.get(future, None)
            if pcap_file:
                logger.info('got sessionizer result from {0}'.format(pcap_file))
                try:
                    # 24h timeout per file.
                    pcap_file_sessions[pcap_file] = future.result(timeout=(24 * 60 * 60))
                    csv_file = csv_filenames[pcap_file]
                    pcap_to_sessioncsv(os.path.dirname(csv_file), pcap_file, pcap_file_sessions[pcap_file])
                except Exception as err:
                    logger.error('exception processing {0}: {1}'.format(pcap_file, err))
        return pcap_file_sessions
