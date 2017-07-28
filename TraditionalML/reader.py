import sys
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
    if data[2] != 'IP':
        return None

    # Parse out the date and time the packet was seen
    date_str = data[0] + ' ' + data[1]
    date = datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')

    # Parse out the source and destination addresses and ports
    source_data = data[3].split('.')
    cutoff = len(source_data) - 1
    source_str = '.'.join(source_data[0:cutoff]) + ':' + source_data[-1]

    destination_data = data[5].split('.')
    cutoff = len(destination_data) - 1
    destination_str = '.'.join(destination_data[0:cutoff]) \
                      + ':' \
                      + destination_data[-1][0:-1]

    return (date, source_str, destination_str)

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
    _, data = raw_data.split(':', 1)
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
    proc = subprocess.Popen(
                            'tcpdump -nn -tttt -xx -r' + path,
                            shell=True,
                            stdout=subprocess.PIPE
                           )
    head = None
    packet_dict = OrderedDict()
    # Go through all the lines of the output
    for line in proc.stdout:
        if not line.startswith(b'\t'):
            head = parse_packet_head(line)
            if head is not None:
                packet_dict[head] = ''
        else:
            data = parse_packet_data(line)
            if head is not None:
                packet_dict[head] += data

    return packet_dict

def sessionizer(path, duration=None):
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

    for head, packet in packet_dict.items():
        time = head[0]

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

        # Add the packet to the appropriate section
        key = (head[1], head[2])
        if key not in working_dict:
            working_dict[key] = []
        working_dict[key].append((head[0],packet))

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)

    return sessions
