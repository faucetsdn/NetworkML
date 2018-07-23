import json
import os
import subprocess
from collections import OrderedDict
import datetime

def parse_packet_head(line):
    '''
    Parses the head of the packet to get the key tuple which contains
    the flow level data

    Args:
        line: Header line from tcpdump

    Returns:
        key: Tuple key which contains packet info
    '''

    # Split the header line into its components
    data = line.decode('utf8')
    data = data.split(' ')

    # Only generate a key if this packet contains IP information
    if len(data) < 2:
        return None

    # Parse out the date and time the packet was seen
    date_str = data[0] + ' ' + data[1]
    try:
        date = datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        return None

    # Parse out the source and destination addresses and ports
    source_data = data[3].split('.')
    destination_data = data[5].split('.')
    destination_port = '0'
    source_port = '0'

    # ipv4 packet
    if data[2] == 'IP':
        # if TCP or UDP set port
        if len(source_data) >= 5:
            source_port = source_data[4]

        source_str = '.'.join(source_data[0:4]) + ':' + source_port
        if len(destination_data) < 5:
            destination_str = '.'.join(destination_data[0:4])[0:-1] \
                              + ':' \
                              + destination_port
        else:
            destination_port = destination_data[4][0:-1]
            destination_str = '.'.join(destination_data[0:4]) \
                              + ':' \
                              + destination_port
    # ipv6 packet
    elif data[2] == 'IP6':
        # if TCP or UDP set port
        if len(source_data) >= 2:
            source_port = source_data[1]

        source_str = source_data[0] + ':' + source_port
        if len(destination_data) < 2:
            destination_str = destination_data[0][0:-1] + ':' + destination_port
        else:
            destination_port = destination_data[1][0:-1]
            destination_str = destination_data[0] \
                              + ':' \
                              + destination_port
    else:
        return None

    return date, source_str, destination_str

def parse_packet_data(line):
    '''
    Parses the hex data from a line in the packet and returns it as a
    string of characters in 0123456789abcdef.

    Args:
        line: Hex output from tcpdump

    Returns:
        packet_data: String containing the packet data
    '''
    raw_data = line.decode('utf-8')
    try:
        _, data = raw_data.split(':', 1)
    except ValueError:
        return None
    packet_data = data.strip().replace(' ' ,'')

    return packet_data

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

    # Read get the pcap info with tcpdump
    FNULL = open(os.devnull, 'w')
    proc = subprocess.Popen(
                            'tcpdump -nn -tttt -xx -r' + path,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=FNULL
                           )
    head = None
    packet_dict = OrderedDict()
    # Go through all the lines of the output
    for line in proc.stdout:
        if not line.startswith(b'\t'):
            head = parse_packet_head(line)
            if head is not None:
                packet_dict[head] = ''
        elif head is not None:
            data = parse_packet_data(line)
            if data is not None:
                packet_dict[head] += data
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

    # Get threshold time from config
    if threshold_time is None:
        try:
            with open('opts/config.json', 'r') as config_file:
                config = json.load(config_file)
                threshold_time  = config['session threshold']
        except Exception as e:
            threshold_time = 120

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
            working_dict[key].append((head[0],packet))

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)
    return sessions
