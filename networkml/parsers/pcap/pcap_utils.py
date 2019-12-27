'''
Utilities for preparing sessions for input into models
'''
import ipaddress
import os
from collections import Counter
from collections import defaultdict
from collections import OrderedDict
import netaddr


def is_private(address):
    '''
    Checks if an address is private and if so returns True.  Otherwise returns
    False.
    Args:
        address: Address to check. Can be list or string
    Returns:
        True or False
    '''
    if isinstance(address, str):
        try:
            return ipaddress.ip_address(address).is_private
        except ValueError:
            return False
    return address.is_private


def mac_from_int(mac_int):
    '''
    Return Unix format MAC address from an integer.
    Args:
        mac_int: MAC address as integer.
    Returns:
        MAC address as Unix string format (fully expanded and lowercase).
    '''
    return str(netaddr.EUI(mac_int, dialect=netaddr.mac_unix_expanded)).lower()


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
    source_mac = mac_from_int(int(source_mac, 16))
    dest_mac = mac_from_int(int(dest_mac, 16))
    return source_mac, dest_mac


def get_indiv_source(sessions, address_type='MAC'):
    '''
    Gets the source MAC address from an individual session dictionary.
    Also computes the number of sessions to and from this source.
    The source is defined to be the IP address with the most sessions
    associated with it.

    Inputs:
        sessions: A dictionary of hex sessions from the sessionizer
        address_type: Type of address to report as the source
    Returns:
        capture_source: Address of the capture source
        ip_mac_pairs: Counts of appearances of ip:mac pairs
    '''

    # Number of sessions involving the address
    ip_mac_pairs = defaultdict(int)

    # Count the incoming/outgoing sessions for all addresses
    for key, session in sessions.items():
        source_address, _ = get_ip_port(key[0])
        destination_address, _ = get_ip_port(key[1])

        # Get the first packet and grab the macs from it
        first_packet = session[0][1]
        source_mac, destination_mac = extract_macs(first_packet)
        pair_1 = '-'.join((str(source_address), source_mac))
        pair_2 = '-'.join((str(destination_address), destination_mac))

        # Compute the IP/MAC address pairs
        if os.environ.get('POSEIDON_PUBLIC_SESSIONS'):
            ip_mac_pairs[pair_1] += 1
            ip_mac_pairs[pair_2] += 1
        else:
            # Only look at sessions with an internal IP address
            # This shouldn't actually be necessary at this stage
            if is_private(source_address):
                ip_mac_pairs[pair_1] += 1
            if is_private(destination_address):
                ip_mac_pairs[pair_2] += 1

    # The address with the most sessions is the capture source
    if sessions:
        most_common_key = max(ip_mac_pairs, key=lambda k: ip_mac_pairs[k]).split('-')
        if address_type == 'MAC':
            capture_source = most_common_key[1]
        else:
            capture_source = most_common_key[0]
        return capture_source, ip_mac_pairs

    return None, ip_mac_pairs


def get_source(sessions, address_type='MAC'):
    '''
    Gets the source MAC for all the session dicts given.  This is the majority
    vote across all session dicts if sessions is a list.

    Args:
        sessions: either a single session dict or a list of session dicts
        address_type: Type of address to return as source identifer
    Returns
        capture_source: Majority MAC address across all sessions in input
    '''

    if isinstance(sessions, list):
        all_pairs = Counter({})
        # Aggregate counts from all binned sessions
        for session_dict in sessions:
            # Get the ip mac address pairs for each session dict
            _, ip_mac_pairs = get_indiv_source(session_dict)
            # Combine with previous stats
            all_pairs += Counter(ip_mac_pairs)
        if all_pairs:
            most_common_key = max(all_pairs, key=lambda k: all_pairs[k]).split('-')
            if address_type == 'MAC':
                capture_source = most_common_key[1]
            else:
                capture_source = ipaddress.ip_address(most_common_key[0])
        else:
            if address_type == 'MAC':
                capture_source = mac_from_int(0)
            else:
                capture_source = ipaddress.ip_address(0)
    else:
        if address_type == 'MAC':
            capture_source, _ = get_indiv_source(sessions)
        else:
            capture_source, _ = get_indiv_source(sessions, address_type='IP')

    return capture_source


def packet_size(packet):
    '''
    Extracts the size of a packet in bytes from the hex header.

    Args:
        packet: Hex header of the packet

    Returns:
        size: Size in bytes of the IP packet, including data
    '''

    try:
        return get_length(packet[1])
    except ValueError:  # pragma: no cover
        return 0


def extract_session_size(session):
    '''
    Extracts the total size of a session in bytes.

    Args:
        session: session list containing all the packets of the session

    Returns:
        session_size: Size of the session in bytes
    '''

    return sum([packet_size(p) for p in session])


def extract_protocol(session):
    '''
    Extracts the protocol used in the session from the first packet

    Args:
        session: session tuple containing all the packets of the session

    Returns:
        protocol: Protocol number used in the session
    '''

    return session[0][1][46:48]


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

    if is_private(address_1) and is_private(address_2):
        return False

    return True


def is_protocol(session, protocol):
    '''
    Checks if a session is of the type specified

    Args:
        session: List of packets in the session
        protocol: Protocol to check

    Returns:
        is_protocol: True or False indicating if this is a TCP session
    '''
    return protocol == extract_protocol(session)


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


def clean_session_dict(sessions, source_address=None):
    '''
    return sessions of packets with no mac or ip addresses from the source
    '''
    if source_address is None:
        source_address = get_source(sessions, address_type='IP')

    def clean_dict(sessions, source_address):
        cleaned_sessions = OrderedDict()
        for key, packets in sessions.items():
            # TODO: Removing port_1 and port_2 (i.e., returned val [1])
            # due to unuse, but I'm a little surprised we aren't using
            # this... O_o
            address_1 = get_ip_port(key[0])[0]
            address_2 = get_ip_port(key[1])[0]

            first_packet = packets[0][1]
            source_mac, destination_mac = extract_macs(first_packet)

            if (address_1 == source_address
                    or source_mac == source_address
                    or address_2 == source_address
                    or destination_mac == source_address):
                if os.environ.get('POSEIDON_PUBLIC_SESSIONS'):
                    cleaned_sessions[key] = [
                        (ts, clean_packet(p))
                        for ts, p in packets[0:8]
                    ]
                else:
                    if is_private(address_1) or is_private(address_2):
                        cleaned_sessions[key] = [
                            (ts, clean_packet(p))
                            for ts, p in packets[0:8]
                        ]
        return cleaned_sessions

    if isinstance(sessions, list):
        cleaned_sessions = [
            clean_dict(sess, source_address) for sess in sessions]
    else:
        cleaned_sessions = clean_dict(sessions, source_address)

    return cleaned_sessions, source_address


def get_length(packet):
    """
    Gets the total length of the packet
    """
    return int(packet[32:36], 16)


def featurize_session(key, packets, source=None):
    # Global session properties
    address_1, _ = get_ip_port(key[0])
    address_2, _ = get_ip_port(key[1])
    if address_1 == source or address_2 == source or source is None:
        initiated_by_source = None
        if address_1 == source:
            initiated_by_source = True
        if address_2 == source:
            initiated_by_source = False

        mac_1, mac_2 = extract_macs(packets[0][1])
        protocol = extract_protocol(packets)
        external = is_external(address_1, address_2)

        # Packet specific properties
        size_to_1 = 0
        size_to_2 = 0

        first_time = packets[0][0].timestamp()
        last_time = packets[-1][0].timestamp()

        num_sent_by_1 = 0
        num_sent_by_2 = 0
        for packet in packets:
            source_mac, _ = extract_macs(packet[1])

            if source_mac == mac_1:
                size_to_2 = get_length(packet[1])
                num_sent_by_1 += 1
            if source_mac == mac_2:
                size_to_1 = get_length(packet[1])
                num_sent_by_2 += 1
        if (num_sent_by_1 + num_sent_by_2) > 1:
            elapsed_time = last_time - first_time
            # don't divide by zero, if no time has elapsed then divide by 1
            if elapsed_time == 0:
                elapsed_time = 1
            freq_1 = num_sent_by_1/elapsed_time
            freq_2 = num_sent_by_2/elapsed_time
        else:
            freq_1 = 1
            freq_2 = 1

        # Netflow-like session info
        session_info = {
            'start time': packets[0][0],
            'initiated by source': initiated_by_source,
            'external session': external,
            'source': key[0],
            'destination': key[1],
            'protocol': protocol,
            'data to source': size_to_1,
            'data to destination': size_to_2,
            'packets to source': num_sent_by_2,
            'packets to destination': num_sent_by_1,
            'source frequency': freq_1,
            'destination frequency': freq_2,
        }
        return session_info
    return None


def get_ip_port(socket_str):
    """
    Returns ip and port
    :param socket_str: ipv4/6:port
    :return:
    address, port
    """
    address, port = socket_str.rsplit(':', 1)
    address = ipaddress.ip_address(address)
    return address, port
