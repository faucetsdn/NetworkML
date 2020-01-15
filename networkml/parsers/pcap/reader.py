import binascii
import datetime
import os
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor, as_completed
import pyshark


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
            data = packet.get_raw_packet()
            head = parse_packet_head(packet)
            if head is not None:
                keys, highest_layers = head
                packet_dict[keys] = binascii.hexlify(data).decode('utf-8')
                for key, highest_layer in highest_layers.items():
                    if key not in highest_layers_dict:
                        highest_layers_dict[key] = set()
                    highest_layers_dict[key].update({highest_layer})
    return packet_dict, highest_layers_dict


def sessionizer(path, duration=None, threshold_time=None):
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

        # Add the session to the session dict if it's start time is after
        # the cutoff
        if key in working_dict:
            working_dict[key].append((head[0], packet))

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)
    return sessions


def parallel_sessionizer(logger, pcap_files, duration=None, threshold_time=None):
    '''
    Run sessionizer() in parallel across many pcap files.

    Args:
        logger: logger instance.
        pcap_files: list of files to process.
        duration and threshold_time: passed to sessionizer().

    Returns:
        dict of session_dicts, keyed by pcap filename.
    '''
    # Process smaller files first - many small files can be processed in parallel.
    pcap_files = sorted(pcap_files, key=os.path.getsize, reverse=True)
    with ProcessPoolExecutor() as executor:
        futures = {
            executor.submit(sessionizer, pcap_file, duration, threshold_time): pcap_file
            for pcap_file in pcap_files}
        pcap_file_sessions = {}
        for future in as_completed(futures):
            pcap_file = futures.get(future, None)
            if pcap_file:
                logger.info('got sessionizer result from {0}'.format(pcap_file))
                try:
                    # 24h timeout per file.
                    pcap_file_sessions[pcap_file] = future.result(timeout=(24 * 60 * 60))
                except Exception as err:
                    logger.error('exception processing {0}: {1}'.format(pcap_file, err))
        return pcap_file_sessions
