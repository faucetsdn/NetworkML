'''
Utilities for preparing sessions for input into models
'''
from collections import OrderedDict, defaultdict

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

def strip_macs(packet):
    '''
    Strip the mac addresses out of a packet
    '''
    return packet[24:]

def strip_ips(stripped_packet):
    '''
    Strip the IP addresses out of a packet that has had its mac addresses
    stripped out
    '''
    return stripped_packet[0:28] + stripped_packet[44:]

def clean_packet(packet):
    '''
    Remove both mac and ip addresses from a packet
    '''
    no_macs = strip_macs(packet)
    no_ips = strip_ips(no_macs)
    return no_ips

def clean_session_dict(sessions, source_ip=None):
    '''
    return sessions of packets with no mac or ip addresses from the source_ip
    '''
    if source_ip is None:
        source_ip = get_source(sessions)

    cleaned_sessions = OrderedDict()
    for key, packets in sessions.items():
        address_1 = key[0].split(':')[0]
        address_2 = key[1].split(':')[0]
        if address_1 == source_ip:
            if is_private(address_1) and is_private(address_2):
                    cleaned_sessions[key] = [
                                             (ts, clean_packet(p))
                                             for ts, p in packets[0:8]
                                            ]
    return cleaned_sessions, source_ip

def create_inputs(session, source_ip=None):
    '''
    Creates model inputs from session
    '''
