from collections import Counter
import ipaddress
import statistics
from numpy import percentile
from networkml.featurizers.features import Features

ETH_TYPE_ARP = 0x806
ETH_TYPE_IP = 0x800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_IPX = 0x8137
ETH_IP_TYPES = frozenset((ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_IPV6))


class Host(Features):

    NAME_TO_STAT = {
        'count': len,
        'max': max,
        'min': min,
        'average': statistics.mean,
        'median': statistics.median,
        'variance': statistics.variance,
        '25q': lambda x: percentile(x, 25),
        '75q': lambda x: percentile(x, 75),
        'total': sum,
    }


    def _calc_tshark_field(self, field, tshark_field, rows):
        field_parts = field.split('_')
        field_prefix = field_parts[0]
        field_suffix = field_parts[-1]
        stat = self.NAME_TO_STAT.get(field_prefix, None)
        assert stat is not None, field_prefix
        rows_filter = rows
        if field_suffix == 'in':
            rows_filter = self._select_mac_direction(rows, output=False)
        elif field_suffix == 'out':
            rows_filter = self._select_mac_direction(rows, output=True)
        new_rows = [{field: self._stat_row_field(stat, tshark_field, rows_filter)}]
        return new_rows


    def _pyshark_ipversions(self, rows):
        ipversions = set()
        for row in self._pyshark_row_layers(rows):
            if '<IP Layer>' in row['layers']:
                ipversions.add(4)
            elif '<IPV6 Layer>' in row['layers']:
                ipversions.add(6)
        return ipversions


    def pyshark_ipv4(self, rows):
        return [{'IPv4': (4 in self._pyshark_ipversions(rows))}]


    def pyshark_ipv6(self, rows):
        return [{'IPv6': (6 in self._pyshark_ipversions(rows))}]


    def pyshark_last_highest_layer(self, rows):
        highest_layer = 0
        for row in self._pyshark_row_layers(rows):
            highest_layer = row['layers'].split('<')[-1]
        return [{'highest_layer': highest_layer}]


    def pyshark_layers(self, rows):
        layers = set()
        for row in self._pyshark_row_layers(rows):
            temp = row['layers'].split('<')[1:]
            layers.update({layer.split(' Layer')[0] for layer in temp})
        return [{layer: 1 for layer in layers}]


    @staticmethod
    def last_protocols(rows):
        protocols = ''
        for row in rows:
            row_protocols = row.get('frame.protocols', None)
            if row_protocols is not None:
                protocols = row_protocols
        new_rows = [{'Protocols': protocols}]
        return new_rows


    def tshark_last_protocols_array(self, rows):
        protocols = set()
        try:
            protocols.update({
                protocol for protocol in self.last_protocols(rows)[0]['Protocols'].split(':') if protocol})
        except IndexError:
            return []
        protocols = protocols - set(['ethertype'])
        return [{'protocol_%s' % protocol: 1 for protocol in protocols}]


    def tshark_ipv4(self, rows):
        return [{'IPv4': int(4 in self._tshark_ipversions(rows))}]


    def tshark_ipv6(self, rows):
        return [{'IPv6': int(6 in self._tshark_ipversions(rows))}]


    def _calc_time_delta(self, field, rows):
        assert 'time_delta' in field
        return self._calc_tshark_field(field, 'frame.time_delta_displayed', rows)


    def _calc_framelen(self, field, rows):
        assert 'frame_len' in field
        return self._calc_tshark_field(field, 'frame.len', rows)


    @staticmethod
    def _get_ips(row):
        ip_src = None
        for src_field in ('ip.src', 'ip.src_host'):
            ip_src = row.get(src_field, None)
            if ip_src:
                break
        ip_dst = None
        for dst_field in ('ip.dst', 'ip.dst_host'):
            ip_dst = row.get(dst_field, None)
            if ip_dst:
                break
        if ip_src and ip_dst:
            ip_src = ipaddress.ip_address(ip_src)
            ip_dst = ipaddress.ip_address(ip_dst)
        return (ip_src, ip_dst)


    @staticmethod
    def _get_proto_eth_type(row):
        for eth_field in ('vlan.etype', 'eth.type'):
            eth_type = row.get(eth_field, None)
            if eth_type:
                return eth_type
        return 0


    @staticmethod
    def _safe_int(maybeint):
        if isinstance(maybeint, int) or maybeint is None:
            return maybeint
        if maybeint:
            return int(maybeint, 0)
        return None


    def _get_ip_proto_ports(self, row, ip_proto):
        src_port = self._safe_int(row.get('.'.join((ip_proto, 'srcport')), None))
        dst_port = self._safe_int(row.get('.'.join((ip_proto, 'dstport')), None))
        return (src_port, dst_port)


    def _lowest_ip_proto_ports(self, rows, ip_proto):
        lowest_ports = set()
        for row in rows:
            src_port, dst_port = self._get_ip_proto_ports(row, ip_proto)
            if src_port and dst_port:
                min_port = min(src_port, dst_port)
                lowest_ports.add(min_port)
        return lowest_ports


    def _priv_ip_proto_ports(self, rows, ip_proto):
        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
        # TODO: enumerate most common ports from survey (complete indicator matrix too expensive)
        wk_ref_priv_proto_ports = frozenset(
            [22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 161, 443, 631])
        lowest_ports = {port for port in self._lowest_ip_proto_ports(rows, ip_proto) if port < 1024}
        priv_ports = {port: int(port in lowest_ports) for port in wk_ref_priv_proto_ports}
        priv_ports.update({'other': int(not lowest_ports.issubset(wk_ref_priv_proto_ports))})
        return priv_ports


    def _nonpriv_ip_proto_ports(self, rows, ip_proto):
        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
        # TODO: enumerate most common ports from survey (complete indicator matrix too expensive)
        wk_ref_nonpriv_proto_ports = frozenset(
            [1900, 2375, 2376, 5222, 5349, 5353, 5354, 5349, 5357, 6653])
        lowest_ports = {port for port in self._lowest_ip_proto_ports(rows, ip_proto) if port >= 1024}
        nonpriv_ports = {port: int(port in lowest_ports) for port in wk_ref_nonpriv_proto_ports}
        nonpriv_ports.update({'other': int(not lowest_ports.issubset(wk_ref_nonpriv_proto_ports))})
        return nonpriv_ports


    def _get_priv_ports(self, rows, ip_proto, suffix):
        priv_ports = self._priv_ip_proto_ports(rows, ip_proto)
        return [{'tshark_%s_priv_port_%s_%s' % (ip_proto, port, suffix): present
            for port, present in priv_ports.items()}]


    def tshark_priv_tcp_ports_in(self, rows):
        rows = self._select_mac_direction(rows, output=False)
        return self._get_priv_ports(rows, 'tcp', 'in')


    def tshark_priv_tcp_ports_out(self, rows):
        rows = self._select_mac_direction(rows, output=True)
        return self._get_priv_ports(rows, 'tcp', 'out')


    def tshark_priv_udp_ports_in(self, rows):
        rows = self._select_mac_direction(rows, output=False)
        return self._get_priv_ports(rows, 'udp', 'in')


    def tshark_priv_udp_ports_out(self, rows):
        rows = self._select_mac_direction(rows, output=True)
        return self._get_priv_ports(rows, 'udp', 'out')


    def _get_nonpriv_ports(self, rows, ip_proto, suffix):
        nonpriv_ports = self._nonpriv_ip_proto_ports(rows, ip_proto)
        return [{'tshark_%s_nonpriv_port_%s_%s' % (ip_proto, port, suffix): present
            for port, present in nonpriv_ports.items()}]


    def tshark_nonpriv_tcp_ports_in(self, rows):
        rows = self._select_mac_direction(rows, output=False)
        return self._get_nonpriv_ports(rows, 'tcp', 'in')


    def tshark_nonpriv_tcp_ports_out(self, rows):
        rows = self._select_mac_direction(rows, output=True)
        return self._get_nonpriv_ports(rows, 'tcp', 'out')


    def tshark_nonpriv_udp_ports_in(self, rows):
        rows = self._select_mac_direction(rows, output=False)
        return self._get_nonpriv_ports(rows, 'udp', 'in')


    def tshark_nonpriv_udp_ports_out(self, rows):
        rows = self._select_mac_direction(rows, output=True)
        return self._get_nonpriv_ports(rows, 'udp', 'out')


    def _get_flags(self, rows, suffix, flags_field, decode_map):
        flags_counter = Counter()
        for decoded_flag in decode_map.values():
            flags_counter[decoded_flag] = 0
        for row in rows:
            flags = self._safe_int(row.get(flags_field, 0))
            if flags:
                for bit, decoded_flag in decode_map.items():
                    if flags & (2**bit):
                        flags_counter[decoded_flag] += 1
        return [{'tshark_%s_%s_%s' % (
            flags_field.replace('.', '_'), decoded_flag, suffix): val
                for decoded_flag, val in flags_counter.items()}]


    def _get_tcp_flags(self, rows, suffix):
        return self._get_flags(rows, suffix, 'tcp.flags',
            {0: 'fin', 1: 'syn', 2: 'rst', 3: 'psh', 4: 'ack',
                5: 'urg', 6: 'ece', 7: 'cwr', 8: 'ns'})


    def tshark_tcp_flags_in(self, rows):
        rows_filter = self._select_mac_direction(rows, output=False)
        return self._get_tcp_flags(rows_filter, 'in')


    def tshark_tcp_flags_out(self, rows):
        rows_filter = self._select_mac_direction(rows, output=True)
        return self._get_tcp_flags(rows_filter, 'out')


    def _get_ip_flags(self, rows, suffix):
        return self._get_flags(rows, suffix, 'ip.flags',
            {13: 'rb', 14: 'df', 15: 'mf'})


    def tshark_ip_flags_in(self, rows):
        rows_filter = self._select_mac_direction(rows, output=False)
        return self._get_ip_flags(rows_filter, 'in')


    def tshark_ip_flags_out(self, rows):
        rows_filter = self._select_mac_direction(rows, output=True)
        return self._get_ip_flags(rows_filter, 'out')


    def _get_ip_dsfield(self, rows, suffix):
        return self._get_flags(rows, suffix, 'ip.dsfield', {
            0: 'ecn0', 1: 'ecn1', 2: 'dscp0', 3: 'dscp1', 4: 'dscp2',
            5: 'dscp3', 6: 'dscp4', 7: 'dscp5'})


    def tshark_ip_dsfield_in(self, rows):
        rows_filter = self._select_mac_direction(rows, output=False)
        return self._get_ip_dsfield(rows_filter, 'in')


    def tshark_ip_dsfield_out(self, rows):
        rows_filter = self._select_mac_direction(rows, output=True)
        return self._get_ip_dsfield(rows_filter, 'out')


    def tshark_wk_ip_protos(self, rows):
        wk_protos = set()
        ref_wk_protos = frozenset(('tcp', 'udp', 'icmp', 'icmp6', 'arp', 'other'))
        for row in rows:
            wk_proto = set(row.keys()).intersection(ref_wk_protos)
            if wk_proto:
                wk_protos.update(wk_proto)
            else:
                wk_protos.add('other')
        return [{'tshark_wk_ip_proto_%s' % wk_proto: int(wk_proto in wk_protos) for wk_proto in ref_wk_protos}]


    @staticmethod
    def tshark_vlan_id(rows):
        vlan_id = 0
        for row in rows:
            vlan_id = row.get('vlan.id', 0)
            if vlan_id:
                break
        return [{'tshark_vlan_id': vlan_id}]


    def tshark_ipx(self, rows):
        ipx = 0
        for row in rows:
            if self._get_proto_eth_type(row) == ETH_TYPE_IPX:
                ipx = 1
                break
        return [{'tshark_ipx': ipx}]


    def tshark_both_private_ip(self, rows):
        both_private = 0
        if rows:
            both_private = 1
            for row in rows:
                ip_src, ip_dst = self._get_ips(row)
                if ip_src and ip_dst:
                    if not (ip_src.is_private and ip_dst.is_private):
                        both_private = 0
                        break
        return [{'tshark_both_private_ip': both_private}]


    def tshark_ipv4_multicast(self, rows):
        multicast = 0
        if rows:
            for row in rows:
                _, ip_dst = self._get_ips(row)
                if ip_dst and ip_dst.version == 4 and ip_dst.is_multicast:
                    multicast = 1
                    break
        return [{'tshark_ipv4_multicast': multicast}]


    def tshark_non_ip(self, rows):
        non_ip = 1
        if rows:
            non_ip = 0
            for row in rows:
                if self._get_proto_eth_type(row) not in ETH_IP_TYPES:
                    non_ip = 1
                    break
        return [{'tshark_non_ip': non_ip}]


    def tshark_average_time_delta(self, rows):
        return self._calc_time_delta('average_time_delta', rows)


    def tshark_min_time_delta(self, rows):
        return self._calc_time_delta('min_time_delta', rows)


    def tshark_max_time_delta(self, rows):
        return self._calc_time_delta('max_time_delta', rows)


    def tshark_average_frame_len(self, rows):
        return self._calc_framelen('average_frame_len', rows)


    def tshark_min_frame_len(self, rows):
        return self._calc_framelen('min_frame_len', rows)


    def tshark_max_frame_len(self, rows):
        return self._calc_framelen('max_frame_len', rows)


    def tshark_median_frame_len(self, rows):
        return self._calc_framelen('median_frame_len', rows)


    def tshark_variance_frame_len(self, rows):
        return self._calc_framelen('variance_frame_len', rows)


    def tshark_25q_frame_len(self, rows):
        return self._calc_framelen('25q_frame_len', rows)


    def tshark_75q_frame_len(self, rows):
        return self._calc_framelen('75q_frame_len', rows)

    # By direction

    def tshark_count_frame_len_in(self, rows):
        return self._calc_framelen('count_frame_len_in', rows)


    def tshark_count_frame_len_out(self, rows):
        return self._calc_framelen('count_frame_len_out', rows)


    def tshark_total_frame_len_in(self, rows):
        return self._calc_framelen('total_frame_len_in', rows)


    def tshark_total_frame_len_out(self, rows):
        return self._calc_framelen('total_frame_len_out', rows)


    def tshark_average_frame_len_in(self, rows):
        return self._calc_framelen('average_frame_len_in', rows)


    def tshark_average_frame_len_out(self, rows):
        return self._calc_framelen('average_frame_len_out', rows)


    def tshark_25q_frame_len_in(self, rows):
        return self._calc_framelen('25q_frame_len_in', rows)


    def tshark_25q_frame_len_out(self, rows):
        return self._calc_framelen('25q_frame_len_out', rows)


    def tshark_75q_frame_len_in(self, rows):
        return self._calc_framelen('75q_frame_len_in', rows)


    def tshark_75q_frame_len_out(self, rows):
        return self._calc_framelen('75q_frame_len_out', rows)


    def tshark_median_frame_len_in(self, rows):
        return self._calc_framelen('median_frame_len_in', rows)


    def tshark_median_frame_len_out(self, rows):
        return self._calc_framelen('median_frame_len_out', rows)


    def tshark_variance_frame_len_in(self, rows):
        return self._calc_framelen('variance_frame_len_in', rows)


    def tshark_variance_frame_len_out(self, rows):
        return self._calc_framelen('variance_frame_len_out', rows)


    def tshark_max_frame_len_in(self, rows):
        return self._calc_framelen('max_frame_len_in', rows)


    def tshark_max_frame_len_out(self, rows):
        return self._calc_framelen('max_frame_len_out', rows)


    def tshark_min_frame_len_in(self, rows):
        return self._calc_framelen('min_frame_len_in', rows)


    def tshark_min_frame_len_out(self, rows):
        return self._calc_framelen('min_frame_len_out', rows)


    def tshark_min_time_delta_in(self, rows):
        return self._calc_time_delta('min_time_delta_in', rows)


    def tshark_min_time_delta_out(self, rows):
        return self._calc_time_delta('min_time_delta_out', rows)


    def tshark_25q_time_delta_in(self, rows):
        return self._calc_time_delta('25q_time_delta_in', rows)


    def tshark_25q_time_delta_out(self, rows):
        return self._calc_time_delta('25q_time_delta_out', rows)


    def tshark_median_time_delta_in(self, rows):
        return self._calc_time_delta('median_time_delta_in', rows)


    def tshark_median_time_delta_out(self, rows):
        return self._calc_time_delta('median_time_delta_out', rows)


    def tshark_average_time_delta_in(self, rows):
        return self._calc_time_delta('average_time_delta_in', rows)


    def tshark_average_time_delta_out(self, rows):
        return self._calc_time_delta('average_time_delta_out', rows)


    def tshark_75q_time_delta_in(self, rows):
        return self._calc_time_delta('75q_time_delta_in', rows)


    def tshark_75q_time_delta_out(self, rows):
        return self._calc_time_delta('75q_time_delta_out', rows)


    def tshark_max_time_delta_in(self, rows):
        return self._calc_time_delta('max_time_delta_in', rows)


    def tshark_max_time_delta_out(self, rows):
        return self._calc_time_delta('max_time_delta_out', rows)


    def tshark_variance_time_delta_in(self, rows):
        return self._calc_time_delta('variance_time_delta_in', rows)


    def tshark_variance_time_delta_out(self, rows):
        return self._calc_time_delta('variance_time_delta_out', rows)
