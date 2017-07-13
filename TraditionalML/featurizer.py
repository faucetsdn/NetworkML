import numpy as np
from collections import defaultdict

def get_source(sessions):
    '''
    Gets the source IP address from a session dictionary.
    Also computes the number of sessions to and from this source.
    The source is defined to be the IP address with the most outgoing
    sessions associated with it.
    Inputs:
        sessions: A dictionary of hex sessions from the sessionizer
    Returns:
        capture_source: Address of the capture source
        num_incoming: # of incoming sessions to the capture source
        num_outgoing: # of outgoing sessions from the capture source
    '''

    # Incoming sessions have the address as the destination
    incoming_sessions = defaultdict(int)
    # Outgoing sessions have the address as the source
    outgoing_sessions = defaultdict(int)

    # Count the incoming/outgoing sessions for all addresses
    for key in sessions:
        incoming_address = key[1].split(':')[0]
        outgoing_address = key[0].split(':')[0]

        incoming_sessions[incoming_address] += 1
        outgoing_sessions[outgoing_address] += 1

    # The address with the most outgoing sessions is the capture source
    if len(sessions) == 0:
        return None, 0, 0

    capture_source = max(
                          outgoing_sessions.keys(),
                          key=(lambda k: outgoing_sessions[k])
                        )

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
    return int(size, 16)

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

def extract_features(session_dict, capture_source=None, max_port=1024):
    '''
    Extracts netflow level features from packet capture. Features are:
        - Number of incoming sessions
        - Number of outgoing sessions
        - Ratio of incoming to outgoing sessions
        - Number of other IPs connected to
        - Number of unique ports used as source or destination
        - # of sessions, packets, and bytes sent/received on each port

    Args:
        pcap_path: path to the packet capture to process into features
        max_port:  Maximum port to get features on (default 1024)

    Returns:
        feature_vector: Vector containing the featurized representation
                        of the input pcap. layout is as follows
                            0 - # of incoming sessions
                            1 - # of outgoing sessions
                            2 - # Ratio of incoming to outgoing sessions
                            3 - # of other IPs connected to
                            4 - # of unique source ports used
                            5 - # of unique destination ports used
                            9*i+m+6 - Feature m on port i
                                m = 0: # of sessions as source
                                m = 1: # of sessions as destination
                                m = 2: # of packets sent from port
                                m = 3: # of packets received from port
                                m = 4: # of bytes sent from port
                                m = 5: # of bytes received from port
                                m = 6: # of TCP sessions on port
                                m = 7: # of UDP sessions on port
                                m = 8: # of ICMP sessions on port
    '''

    # If the capture source isn't specified, default to the most used address
    if capture_source is None:
        capture_source = get_source(session_dict)

    # Compute port specific features for the capture source 
    source_ports, sent_packets, sent_bytes = [
                                              defaultdict(int),
                                              defaultdict(int),
                                              defaultdict(int)
                                             ]

    destination_ports, received_packets, received_bytes = [
                                                           defaultdict(int),
                                                           defaultdict(int),
                                                           defaultdict(int)
                                                          ]

    tcp_sessions, udp_sessions, icmp_sessions = [
                                                 defaultdict(int),
                                                 defaultdict(int),
                                                 defaultdict(int)
                                                ]
    other_ips = defaultdict(int)
    num_incoming = 0
    num_outgoing = 0

    # Iterate over all the sessions and aggregate the port specific info
    for key, session in session_dict.items():
        address_1, port_1 = key[0].split(':')
        address_2, port_2 = key[1].split(':')

        protocol = extract_protocol(session)

        if address_1 == capture_source:
            num_outgoing += 1
            if int(port_1) <= max_port:
                source_ports[port_1] += 1
                sent_packets[port_1] += len(session)
                sent_bytes[port_1] += extract_session_size(session)
                if protocol == '06': tcp_sessions[port_1] += 1
                if protocol == '11': udp_sessions[port_1] += 1
                if protocol == '01': icmp_sessions[port_1] += 1

            if int(port_2) <= max_port:
                destination_ports[port_2] += 1
                received_packets[port_2] += len(session)
                received_bytes[port_2] += extract_session_size(session)
                if protocol == '06': tcp_sessions[port_2] += 1
                if protocol == '11': udp_sessions[port_2] += 1
                if protocol == '01': icmp_sessions[port_2] += 1

            other_ips[address_2] += 1

        if address_2 == capture_source:
            num_incoming += 1
            other_ips[address_1] += 1

    port_aspects = [
                    source_ports,
                    destination_ports,
                    sent_packets,
                    received_packets,
                    sent_bytes,
                    received_bytes,
                    tcp_sessions,
                    udp_sessions,
                    icmp_sessions
                   ]

    num_features = 6 + (max_port+1)*len(port_aspects)
    if num_outgoing == 0:
        io_ratio = 1
    else:
        io_ratio = num_incoming/num_outgoing

    feature_vector = np.zeros(num_features)
    feature_vector[0] = num_incoming
    feature_vector[1] = num_outgoing
    feature_vector[2] = io_ratio
    feature_vector[3] = len(other_ips)
    feature_vector[4] = len(source_ports)
    feature_vector[5] = len(destination_ports)

    for m, aspect in enumerate(port_aspects):
        for port in aspect:
            feature_vector[len(port_aspects)*int(port) + m + 6] = aspect[port]

    return feature_vector

def feature_info(feature_id):
    '''
    Function that gives human readable info about a feature

    Args:
        feature_id: ID number of feature in question

    Returns
        i: Port number the feature relates to
        feature_str: String describing the feature
    '''

    if feature_id == 0:
        return None, "Number of incoming sessions"
    if feature_id == 1:
        return None, "Number of outgoing sessions"
    if feature_id == 2:
        return None, "Ratio of incoming to outgoing sessions"
    if feature_id == 3:
        return None, "Number of other IPs connected to"
    if feature_id == 4:
        return None, "Number of unique source ports used"
    if feature_id == 5:
        return None, "Number of unique destination ports used"

    m = (feature_id - 6) % 9
    i = int((feature_id - 6 - m)/9)

    if m == 0:
        return i, "Number of sessions from port " + str(i)
    if m == 1:
        return i, "Number of sessions to port " + str(i)
    if m == 2:
        return i, "Number of packets sent from port " + str(i)
    if m == 3:
        return i, "Number of packets received from port " + str(i)
    if m == 4:
        return i, "Number of bytes sent from port " + str(i)
    if m == 5:
        return i, "Number of bytes received from port " + str(i)
    if m == 6:
        return i, "Number of TCP sessions on port " + str(i)
    if m == 7:
        return i, "Number of UDP sessions on port " + str(i)
    if m == 8:
        return i, "Number of ICMP sessions on port " + str(i)
