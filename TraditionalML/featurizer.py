import numpy as np
from collections import defaultdict

def is_private(address):
    '''
    Checks if an address is private and if so returns True.  Otherwise returns
    False.

    Args:
        address: Address to check. Can be list or string
    Returns:
        True or False
    '''
    if len(address) > 4:
        pairs = address.split('.')
    elif len(address) == 4:
        pairs = address

    private = False
    if pairs[0] == '10': private = True
    if pairs[0] == '192' and pairs[1] == '168': private = True
    if pairs[0] == '172' and 16 <= int(pairs[1]) <= 31: private = True

    return private

def get_source(sessions):
    '''
    Gets the source IP address from a session dictionary.
    Also computes the number of sessions to and from this source.
    The source is defined to be the IP address with the most sessions
    associated with it.

    Inputs:
        sessions: A dictionary of hex sessions from the sessionizer
    Returns:
        capture_source: Address of the capture source
        num_incoming: # of incoming sessions to the capture source
        num_outgoing: # of outgoing sessions from the capture source
    '''

    # Number of sessions involving the address
    all_sessions = defaultdict(int)
    # Incoming sessions have the address as the destination
    incoming_sessions = defaultdict(int)
    # Outgoing sessions have the address as the source
    outgoing_sessions = defaultdict(int)

    # Count the incoming/outgoing sessions for all addresses
    for key in sessions:
        incoming_address = key[1].split(':')[0]
        outgoing_address = key[0].split(':')[0]

        all_sessions[incoming_address] += 1
        all_sessions[outgoing_address] += 1
        incoming_sessions[incoming_address] += 1
        outgoing_sessions[outgoing_address] += 1

    # The address with the most sessions is the capture source
    if len(sessions) == 0:
        return None, 0, 0

    sorted_sources = sorted(
                            all_sessions.keys(),
                            key=(lambda k: all_sessions[k]),
                            reverse=True
                           )
    capture_source = '0.0.0.0'
    for source in sorted_sources:
        pairs = source.split('.')
        if is_private(pairs):
            capture_source = source
            break

    # Get the incoming/outgoing sessions for the capture source
    num_incoming = incoming_sessions[capture_source]
    num_outgoing = outgoing_sessions[capture_source]

    return capture_source

def packet_size(packet):
    '''
    Extracts the size of a packet in bytes from the hex header.

    Args:
        packet: Hex header of the packet

    Returns:
        size: Size in bytes of the IP packet, including data
    '''

    size = packet[1][32:36]
    try:
        size = int(size, 16)
    except:
        size = 0

    return size

def extract_session_size(session):
    '''
    Extracts the total size of a session in bytes.

    Args:
        session: session list containing all the packets of the session

    Returns:
        session_size: Size of the session in bytes
    '''

    session_size = sum([packet_size(p) for p in session])
    return session_size

def extract_protocol(session):
    '''
    Extracts the protocol used in the session from the first packet

    Args:
        session: session tuple containing all the packets of the session

    Returns:
        protocol: Protocol number used in the session
    '''

    protocol = session[0][1][46:48]
    return protocol

def is_external(address_1, address_2):
    '''
    Checks if a session is between two sources within the same network.
    For now this is defined as two IPs with the first octet matching.

    Args:
        address_1: Address of source participant
        address_2: Address of destination participant

    Returns:
        is_external: True or False if this is an internal session
    '''

    if address_1[0:3] == address_2[0:3]:
        return True

    return False

def is_protocol(session, protocol):
    '''
    Checks if a session is of the type specified

    Args:
        session: List of packets in the session
        protocol: Protocol to check

    Returns:
        is_protocol: True or False indicating if this is a TCP session
    '''

    p = extract_protocol(session)
    if protocol == p:
        return True
    return False

def extract_features(session_dict, capture_source=None, max_port=1024):
    '''
    Extracts netflow level features from packet capture.

    Args:
        pcap_path: path to the packet capture to process into features
        max_port:  Maximum port to get features on (default 1024)

    Returns:
        feature_vector: Vector containing the featurized representation
                        of the input pcap.
    '''

    # If the capture source isn't specified, default to the most used address
    if capture_source is None:
        capture_source = get_source(session_dict)

    # Initialize some counter variables
    num_source_sess = [0]*max_port
    num_destination_sess = [0]*max_port
    num_sessions = 0
    num_external = 0
    num_tcp_sess = 0
    num_udp_sess = 0
    num_icmp_sess = 0

    # Iterate over all sessions and aggregate the info
    other_ips = defaultdict(int)
    for key, session in session_dict.items():
        address_1, port_1 = key[0].split(':')
        address_2, port_2 = key[1].split(':')
        if address_1 == capture_source:
            if is_private(address_2):
                other_ips[address_2] += 1
            num_sessions += 1
            num_external += is_external(address_1, address_2)
            num_tcp_sess += is_protocol(session, '06')
            num_udp_sess += is_protocol(session, '11')
            num_icmp_sess += is_protocol(session, '01')
            if int(port_1) < max_port:
                num_source_sess[int(port_1)] += 1
            if int(port_2) < max_port:
                num_destination_sess[int(port_2)] += 1

        if address_2 == capture_source:
            if is_private(address_1):
                other_ips[address_1] += 1

    num_port_sess = np.concatenate(
                                   (num_source_sess, num_destination_sess),
                                    axis=0
                                  )
    if num_sessions == 0: num_sessions += 1
    num_port_sess = np.asarray(num_port_sess)/num_sessions
    extra_features = [0]*4
    extra_features[0] = num_external/num_sessions
    extra_features[1] = num_tcp_sess/num_sessions
    extra_features[2] = num_udp_sess/num_sessions
    extra_features[3] = num_icmp_sess/num_sessions

    feature_vector = np.concatenate((num_port_sess, extra_features), axis=0)
    return feature_vector, capture_source, list(other_ips.keys())
