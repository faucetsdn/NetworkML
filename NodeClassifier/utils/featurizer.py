import numpy as np
from collections import defaultdict
from collections import Counter
import json

def extract_macs(packet):
    '''
    Takes in hex representation of a packet header and extracts the
    source and destination mac addresses

    returns:
        source_mac: Destination MAC address
        destination_mac: Destination MAC address
    '''

    source_mac = packet[12:24]
    dest_mac = packet[0:12]

    source_mac = ':'.join(source_mac[i:i+2]
                          for i in range(0,len(source_mac), 2)
                         )
    destination_mac = ':'.join(dest_mac[i:i+2]
                               for i in range(0,len(dest_mac),2)
                              )

    return source_mac, destination_mac

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

def get_indiv_source(sessions):
    '''
    Gets the source MAC address from an individual session dictionary.
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
    all_ips= defaultdict(int)
    all_macs = defaultdict(int)
    # Incoming sessions have the address as the destination
    incoming_ips = defaultdict(int)
    incoming_macs = defaultdict(int)
    # Outgoing sessions have the address as the source
    outgoing_ips = defaultdict(int)
    outgoing_macs = defaultdict(int)

    # Count the incoming/outgoing sessions for all addresses
    for key in sessions:
        incoming_address = key[1].split(':')[0]
        outgoing_address = key[0].split(':')[0]

        # Get the first packet and grab the macs from it
        first_packet = sessions[key][0][1]
        source_mac, destination_mac = extract_macs(first_packet)

        # Only look at internal <-> internal sessions
        if is_private(incoming_address) or is_private(outgoing_address):
            # Store the data
            all_ips[incoming_address] += 1
            all_ips[outgoing_address] += 1
            all_macs[source_mac] += 1
            all_macs[destination_mac] += 1

            incoming_ips[incoming_address] += 1
            incoming_macs[source_mac] += 1

            outgoing_ips[outgoing_address] += 1
            outgoing_ips[destination_mac] += 1

    # The address with the most sessions is the capture source
    if len(sessions) == 0:
        return None, all_macs, all_ips

    sorted_sources = sorted(
                            all_macs.keys(),
                            key=(lambda k: incoming_macs[k]),
                            reverse=True
                           )
    capture_source = '00:00:00:00:00:00'
    if len(sorted_sources) > 0:
        capture_source = sorted_sources[0]

    # Get the incoming/outgoing sessions for the capture source
    num_incoming = incoming_macs[capture_source]
    num_outgoing = outgoing_macs[capture_source]

    return capture_source, all_macs, all_ips

def get_source(sessions, address_type='MAC'):
    '''
    Gets the source MAC for all the session dicts given.  This is the majority
    vote across all session dicts if sessions is a list.

    Args:
        sessions: either a single session dict or a list of session dicts
    Returns
        capture_source: Majority MAC address across all sessions in input
    '''

    if type(sessions) is list:
        all_addresses = Counter({})
        # Aggregate counts from all binned sessions
        if address_type == 'MAC':
            capture_source = '00:00:00:00:00:00'
        else:
            capture_source = '0.0.0.0'

        for session_dict in sessions:
            if address_type == 'MAC':
                capture_source = '00:00:00:00:00:00'
                _, indiv_addresses, _ = get_indiv_source(session_dict)
            else:
                _, _, indiv_addresses = get_indiv_source(session_dict)
                capture_source = '0.0.0.0'
            # Combine with previous stats
            all_addresses += Counter(indiv_addresses)

        # Find the most common address
        sorted_sources = sorted(
                                all_addresses.keys(),
                                key=(lambda k: all_addresses[k]),
                                reverse=True
                               )
        if len(sorted_sources) > 0:
            capture_source = sorted_sources[0]

    else:
        if address_type == 'MAC':
            capture_source = '00:00:00:00:00:00'
            _, indiv_addresses, _ = get_indiv_source(sessions)
        else:
            _, _, indiv_addresses = get_indiv_source(sessions)
            capture_source = '0.0.0.0'

        # Find the most common address
        sorted_sources = sorted(
                                indiv_addresses.keys(),
                                key=(lambda k: indiv_addresses[k]),
                                reverse=True
                               )
        if len(sorted_sources) > 0:
            capture_source = sorted_sources[0]

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

def extract_features(session_dict, capture_source=None, max_port=None):
    '''
    Extracts netflow level features from packet capture.

    Args:
        pcap_path: path to the packet capture to process into features
        max_port:  Maximum port to get features on (default to reading config)

    Returns:
        feature_vector: Vector containing the featurized representation
                        of the input pcap.
    '''

    # Get featurization info from config
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            address_type = config['source identifier']
            if max_port is None:
                max_port = config['max port']
    except:
        address_type = 'MAC'
        
    # If the capture source isn't specified, default to the most used address
    if capture_source is None:
        capture_source = get_source(session_dict, address_type=address_type)

    # Initialize some counter variables
    num_sport_init = [0]*max_port
    num_dport_init = [0]*max_port
    num_sport_rec = [0]*max_port
    num_dport_rec = [0]*max_port

    num_sessions_init = 0
    num_external_init = 0
    num_tcp_sess_init = 0
    num_udp_sess_init = 0
    num_icmp_sess_init = 0

    num_sessions_rec = 0
    num_external_rec = 0
    num_tcp_sess_rec = 0
    num_udp_sess_rec = 0
    num_icmp_sess_rec = 0

    # Iterate over all sessions and aggregate the info
    other_ips = defaultdict(int)
    for key, session in session_dict.items():
        address_1, port_1 = key[0].split(':')
        address_2, port_2 = key[1].split(':')

        # Get the first packet and grab the macs from it
        first_packet = session[0][1]
        source_mac, destination_mac = extract_macs(first_packet)

        # If the source is the cpature source
        if (source_mac == capture_source
            or address_1 == capture_source):

            if is_private(address_2):
                other_ips[address_2] += 1

            num_sessions_init += 1
            num_external_init += is_external(address_1, address_2)
            num_tcp_sess_init += is_protocol(session, '06')
            num_udp_sess_init += is_protocol(session, '11')
            num_icmp_sess_init += is_protocol(session, '01')

            if int(port_1) < max_port:
                num_sport_init[int(port_1)] += 1

            if int(port_2) < max_port:
                num_dport_init[int(port_2)] += 1

        # If the destination is the capture source
        if (destination_mac == capture_source
            or address_2 == capture_source):
            if is_private(address_1):
                other_ips[address_1] += 1

            num_sessions_rec += 1
            num_external_rec += is_external(address_2, address_1)
            num_tcp_sess_rec += is_protocol(session, '06')
            num_udp_sess_rec += is_protocol(session, '11')
            num_icmp_sess_rec += is_protocol(session, '01')

            if int(port_1) < max_port:
                num_sport_rec[int(port_1)] += 1
            if int(port_2) < max_port:
                num_dport_rec[int(port_2)] += 1

    num_port_sess = np.concatenate(
                                   (
                                   num_sport_init,
                                   num_dport_init,
                                   num_sport_rec,
                                   num_dport_rec
                                   ),
                                    axis=0
                                  )

    if num_sessions_init == 0:
        num_sessions_init += 1
    if num_sessions_rec == 0:
        num_sessions_rec += 1

    num_port_sess=np.asarray(num_port_sess)/(num_sessions_init+num_sessions_rec)

    extra_features = [0]*8
    extra_features[0] = num_external_init/num_sessions_init
    extra_features[1] = num_tcp_sess_init/num_sessions_init
    extra_features[2] = num_udp_sess_init/num_sessions_init
    extra_features[3] = num_icmp_sess_init/num_sessions_init

    extra_features[4] = num_external_rec/num_sessions_rec
    extra_features[5] = num_tcp_sess_rec/num_sessions_rec
    extra_features[6] = num_udp_sess_rec/num_sessions_rec
    extra_features[7] = num_icmp_sess_rec/num_sessions_rec

    feature_vector = np.concatenate((num_port_sess, extra_features), axis=0)
    return feature_vector, capture_source, list(other_ips.keys())
