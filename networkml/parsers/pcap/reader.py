import datetime
import json
import os
import subprocess
from collections import OrderedDict


def parse_packet_head(layers_json):
    '''
    Parses the head of the packet to get the key tuple which contains
    the flow level data

    Args:
        line: Header line from tcpdump

    Returns:
        key: Tuple key which contains packet info
    '''
    # TODO: should be using utcfromtimestamp()
    try:
        date = datetime.datetime.fromtimestamp(float(layers_json['frame']['frame.time_epoch']))
    except (ValueError, KeyError):
        return None

    src_address = None
    dst_address = None

    for ip_type in ('ip', 'ipv6'):
        try:
            src_address = layers_json[ip_type]['%s.src' % ip_type]
            dst_address = layers_json[ip_type]['%s.dst' % ip_type]
            break
        except KeyError:
            continue

    src_port = '0'
    dst_port = '0'

    for ip_proto_type in ('tcp', 'udp'):
        try:
            src_port = layers_json[ip_proto_type]['%s.srcport' % ip_proto_type]
            dst_port = layers_json[ip_proto_type]['%s.dstport' % ip_proto_type]
            break
        except KeyError:
            continue

    if src_address and dst_address:
        return date, ':'.join((src_address, src_port)), ':'.join((dst_address, dst_port))

    return None


def parse_packet_data(layers_json):
    '''
    Parses the hex data from a line in the packet and returns it as a
    string of characters in 0123456789abcdef.

    Args:
        line: Hex output from tcpdump

    Returns:
        packet_data: String containing the packet data
    '''
    return layers_json['frame_raw'][0]


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

    def parse_buf(buf):
        if not buf:
            return
        packet_json = json.loads(buf)
        try:
            layers_json = packet_json['_source']['layers']
        except KeyError:
            return
        head = parse_packet_head(layers_json)
        data = parse_packet_data(layers_json)
        if head is not None and data is not None:
            packet_dict[head] = data

    # Read get the pcap info with tcpdump
    FNULL = open(os.devnull, 'w')
    proc = subprocess.Popen(
        ['tshark', '-n', '-T', 'json', '-x', '-r', path, '-o', 'tcp.desegment_tcp_streams:false'],
        stdout=subprocess.PIPE,
        stderr=FNULL
    )
    packet_dict = OrderedDict()
    buf = ''
    for line in proc.stdout:
        line = line.decode('utf-8')
        if not line.startswith(' '):
            continue
        if line.startswith('  ,'):
            continue
        buf += line
        if line.startswith('  }'):
            parse_buf(buf)
            buf = ''
    return packet_dict


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
    packet_dict = packetizer(path)

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
