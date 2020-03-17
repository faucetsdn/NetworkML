from collections import Counter, defaultdict
import statistics
from numpy import percentile
import netaddr
from networkml.featurizers.features import Features


MAC_BCAST = netaddr.EUI('FF-FF-FF-FF-FF-FF')
ETH_TYPE_ARP = 0x806
ETH_TYPE_IP = 0x800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_IPX = 0x8137
ETH_IP_TYPES = frozenset((ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_IPV6))


class HostBase:

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

    # http://www.iana.org/assignments/protocol-numbers
    WK_PROTOCOLS = frozenset(['eth', 'ipv6', 'ip', 'tcp', 'arp', 'icmp', 'gre', 'esp'])
    # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
    # TODO: enumerate most common ports from survey (complete indicator matrix too expensive)
    WK_PRIV_PROTO_PORTS = frozenset(
        [22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 161, 443, 631])
    WK_NONPRIV_PROTO_PORTS = frozenset(
        [1900, 2375, 2376, 5222, 5349, 5353, 5354, 5349, 5357, 6653])
    WK_PROTOS = frozenset(('tcp', 'udp', 'icmp', 'icmpv6', 'arp', 'other'))

    @staticmethod
    def _is_unicast(mac):
        mac_val = netaddr.EUI(mac)
        if mac_val == MAC_BCAST or netaddr.EUI(mac_val).packed[0] & 1:
            return False
        return True

    def _tshark_input_mac(self, rows):
        '''Infer MAC address of host connected to a port, from pcap.

           Pick the host that most often occurs as both source and destination.
        '''
        eth_srcs = Counter()
        eth_dsts = Counter()
        all_eths = Counter()

        for row in rows:
            eth_src = row.get('eth.src', None)
            if eth_src and self._is_unicast(eth_src):
                eth_srcs[eth_src] += 1
                all_eths[eth_src] += 1
            eth_dst = row.get('eth.dst', None)
            if eth_dst and self._is_unicast(eth_dst):
                eth_dsts[eth_dst] += 1
                all_eths[eth_dst] += 1

        common_eth = set(eth_srcs).union(eth_dsts)
        if len(common_eth) > 1:
            common_count = [(eth, all_eths[eth]) for eth in common_eth]
            max_eth = sorted(common_count, key=lambda x: x[1])[-1][0]
            return (max_eth, set(all_eths.keys()))
        return (None, None)

    def _select_mac_direction(self, rows, output=True):
        '''Return filter expression selecting input or output rows.'''
        src_mac, all_macs = self._tshark_input_mac(rows)
        # Select all if can't infer direction.
        if src_mac is None or len(all_macs) == 1:
            return rows
        if output:
            # Select all rows where traffic originated by inferred source MAC
            return filter(lambda row: (row.get('eth.src', None) == src_mac), rows)
        # Select all rows where traffic not originated by inferred source MAC.
        return filter(lambda row: (row.get('eth.src', None) != src_mac), rows)

    def _pyshark_ipversions(self, rows_f):
        ipversions = set()
        for row in self._pyshark_row_layers(rows_f):  # pytype: disable=attribute-error
            if '<IP Layer>' in row['layers']:
                ipversions.add(4)
            elif '<IPV6 Layer>' in row['layers']:
                ipversions.add(6)
        return ipversions

    def _pyshark_ipversion(self, version, rows):
        return [{'IPv%u' % version: int(version in self._pyshark_ipversions(rows))}]

    @staticmethod
    def _last_protocols(rows):
        protocols = ''
        for row in rows:
            row_protocols = row.get('frame.protocols', None)
            if row_protocols is not None:
                protocols = row_protocols
        return protocols

    def _row_keys(self, row):
        return set()

    def _partition_rows_by_field_vals(self, rows, all_rows):
        partitioned_rows = defaultdict(list)
        if all_rows is not None:
            for row in all_rows:
                for key in self._row_keys(row):
                    partitioned_rows[key] = []
        for row in rows:
            for key in self._row_keys(row):
                partitioned_rows[key].append(row)
        return partitioned_rows

    def _host_rows(self, rows, host_func, all_rows=None):
        newrows = []
        for host_key, host_rows in self._partition_rows_by_field_vals(rows, all_rows).items():
            host_func_results = host_func(host_rows)
            host_func_results.update({'host_key': host_key})
            newrows.append(host_func_results)
        return newrows

    def _calc_tshark_field(self, field, tshark_field, rows, all_rows=None):

        def calc_field(host_rows):
            field_parts = field.split('_')
            field_prefix = field_parts[0]
            field_suffix = field_parts[-1]
            stat = self.NAME_TO_STAT.get(field_prefix, None)
            assert stat is not None, field_prefix
            rows_filter = host_rows
            if field_suffix == 'in':
                rows_filter = self._select_mac_direction(host_rows, output=False)
            elif field_suffix == 'out':
                rows_filter = self._select_mac_direction(host_rows, output=True)
            return {field: self._stat_row_field(stat, tshark_field, rows_filter)}  # pytype: disable=attribute-error

        return self._host_rows(rows, calc_field, all_rows=all_rows)

    def _calc_time_delta(self, field, rows_f):
        assert 'time_delta' in field
        rows = list(rows_f())
        return self._calc_tshark_field(field, 'frame.time_delta_displayed', rows)

    def _calc_framelen(self, field, rows_f):
        assert 'frame_len' in field
        rows = list(rows_f())
        return self._calc_tshark_field(field, 'frame.len', rows)

    def _get_ip_proto_ports(self, row, ip_proto):
        src_port = self._safe_int(row.get('.'.join((ip_proto, 'srcport')), None))  # pytype: disable=attribute-error
        dst_port = self._safe_int(row.get('.'.join((ip_proto, 'dstport')), None))  # pytype: disable=attribute-error
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
        lowest_ports = {port for port in self._lowest_ip_proto_ports(rows, ip_proto) if port < 1024}
        priv_ports = {port: int(port in lowest_ports) for port in self.WK_PRIV_PROTO_PORTS}
        priv_ports.update({'other': int(not lowest_ports.issubset(self.WK_PRIV_PROTO_PORTS))})
        return priv_ports

    def _nonpriv_ip_proto_ports(self, rows, ip_proto):
        lowest_ports = {port for port in self._lowest_ip_proto_ports(rows, ip_proto) if port >= 1024}
        nonpriv_ports = {port: int(port in lowest_ports) for port in self.WK_NONPRIV_PROTO_PORTS}
        nonpriv_ports.update({'other': int(not lowest_ports.issubset(self.WK_NONPRIV_PROTO_PORTS))})
        return nonpriv_ports

    def _get_priv_ports(self, rows, ip_proto, suffix, all_rows=None):

        def priv_ports_present(host_rows):
            priv_ports = self._priv_ip_proto_ports(host_rows, ip_proto)
            return {'tshark_%s_priv_port_%s_%s' % (ip_proto, port, suffix): present
                    for port, present in priv_ports.items()}

        return self._host_rows(rows, priv_ports_present, all_rows=all_rows)

    def _get_nonpriv_ports(self, rows, ip_proto, suffix, all_rows=None):

        def nonpriv_ports_present(host_rows):
            nonpriv_ports = self._nonpriv_ip_proto_ports(host_rows, ip_proto)
            return {'tshark_%s_nonpriv_port_%s_%s' % (ip_proto, port, suffix): present
                    for port, present in nonpriv_ports.items()}

        return self._host_rows(rows, nonpriv_ports_present, all_rows=all_rows)

    def _get_flags(self, rows, suffix, flags_field, decode_map):
        flags_counter = Counter()
        for decoded_flag in decode_map.values():  # pytype: disable=attribute-error
            flags_counter[decoded_flag] = 0
        for row in rows:
            flags = self._safe_int(row.get(flags_field, 0))  # pytype: disable=attribute-error
            if flags:
                for bit, decoded_flag in decode_map.items():
                    if flags & (2**bit):
                        flags_counter[decoded_flag] += 1
        return {'tshark_%s_%s_%s' % (
            flags_field.replace('.', '_'), decoded_flag, suffix): val
                for decoded_flag, val in flags_counter.items()}

    def _get_tcp_flags(self, rows, suffix):
        return self._get_flags(
            rows, suffix, 'tcp.flags',
            {0: 'fin', 1: 'syn', 2: 'rst', 3: 'psh', 4: 'ack', 5: 'urg', 6: 'ece', 7: 'cwr', 8: 'ns'})

    def _get_ip_flags(self, rows, suffix):
        return self._get_flags(
            rows, suffix, 'ip.flags', {13: 'rb', 14: 'df', 15: 'mf'})

    def _get_ip_dsfield(self, rows, suffix):
        return self._get_flags(rows, suffix, 'ip.dsfield', {
            0: 'ecn0', 1: 'ecn1', 2: 'dscp0', 3: 'dscp1', 4: 'dscp2',
            5: 'dscp3', 6: 'dscp4', 7: 'dscp5'})

    def _pyshark_ipv4(self, rows_f):
        return self._pyshark_ipversion(4, rows_f)

    def _pyshark_ipv6(self, rows_f):
        return self._pyshark_ipversion(6, rows_f)

    def _pyshark_last_highest_layer(self, rows):
        highest_layer = 0
        for row in self._pyshark_row_layers(rows):  # pytype: disable=attribute-error
            highest_layer = row['layers'].split('<')[-1]
        return [{'highest_layer': highest_layer}]

    def _pyshark_layers(self, rows):
        layers = set()
        for row in self._pyshark_row_layers(rows):  # pytype: disable=attribute-error
            temp = row['layers'].split('<')[1:]
            layers.update({layer.split(' Layer')[0] for layer in temp})
        return [{layer: 1 for layer in layers}]

    def _tshark_last_protocols_array(self, rows_f):

        def last_protocols_array(host_rows):
            raw_protocols = set()
            try:
                raw_protocols.update({
                    protocol for protocol in self._last_protocols(host_rows).split(':') if protocol})
            except IndexError:
                pass
            raw_protocols -= set(['ethertype'])
            protocols = {'protocol_%s' % protocol: int(protocol in raw_protocols) for protocol in self.WK_PROTOCOLS}
            protocols.update({'other': int(not raw_protocols.issubset(self.WK_PROTOCOLS))})
            return protocols

        rows = list(rows_f())
        return self._host_rows(rows, last_protocols_array)

    def _tshark_ipv4(self, rows_f):
        rows = list(rows_f())
        return self._host_rows(rows, lambda x: {'IPv4': int(4 in self._tshark_ipversions(x))})

    def _tshark_ipv6(self, rows_f):
        rows = list(rows_f())
        return self._host_rows(rows, lambda x: {'IPv6': int(6 in self._tshark_ipversions(x))})

    def _tshark_priv_tcp_ports_in(self, rows_f):
        rows = list(rows_f())
        in_rows = self._select_mac_direction(rows, output=False)
        return self._get_priv_ports(in_rows, 'tcp', 'in', all_rows=rows)

    def _tshark_priv_tcp_ports_out(self, rows_f):
        rows = list(rows_f())
        out_rows = self._select_mac_direction(rows, output=True)
        return self._get_priv_ports(out_rows, 'tcp', 'out', all_rows=rows)

    def _tshark_priv_udp_ports_in(self, rows_f):
        rows = list(rows_f())
        in_rows = self._select_mac_direction(rows, output=False)
        return self._get_priv_ports(in_rows, 'udp', 'in', all_rows=rows)

    def _tshark_priv_udp_ports_out(self, rows_f):
        rows = list(rows_f())
        out_rows = self._select_mac_direction(rows, output=True)
        return self._get_priv_ports(out_rows, 'udp', 'out', all_rows=rows)

    def _tshark_nonpriv_tcp_ports_in(self, rows_f):
        rows = list(rows_f())
        in_rows = self._select_mac_direction(rows, output=False)
        return self._get_nonpriv_ports(in_rows, 'tcp', 'in', all_rows=rows)

    def _tshark_nonpriv_tcp_ports_out(self, rows_f):
        rows = list(rows_f())
        out_rows = self._select_mac_direction(rows, output=True)
        return self._get_nonpriv_ports(out_rows, 'tcp', 'out', all_rows=rows)

    def _tshark_nonpriv_udp_ports_in(self, rows_f):
        rows = list(rows_f())
        in_rows = self._select_mac_direction(rows, output=False)
        return self._get_nonpriv_ports(in_rows, 'udp', 'in', all_rows=rows)

    def _tshark_nonpriv_udp_ports_out(self, rows_f):
        rows = list(rows_f())
        out_rows = self._select_mac_direction(rows, output=True)
        return self._get_nonpriv_ports(out_rows, 'udp', 'out', all_rows=rows)

    def _tshark_tcp_flags_in(self, rows_f):

        def tcp_flags_in(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=False)
            return self._get_tcp_flags(rows_filter, 'in')

        rows = list(rows_f())
        return self._host_rows(rows, tcp_flags_in)

    def _tshark_tcp_flags_out(self, rows_f):

        def tcp_flags_out(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=True)
            return self._get_tcp_flags(rows_filter, 'out')

        rows = list(rows_f())
        return self._host_rows(rows, tcp_flags_out)

    def _tshark_ip_flags_in(self, rows_f):

        def ip_flags_in(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=False)
            return self._get_ip_flags(rows_filter, 'in')

        rows = list(rows_f())
        return self._host_rows(rows, ip_flags_in)

    def _tshark_ip_flags_out(self, rows_f):

        def ip_flags_out(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=True)
            return self._get_ip_flags(rows_filter, 'out')

        rows = list(rows_f())
        return self._host_rows(rows, ip_flags_out)

    def _tshark_ip_dsfield_in(self, rows_f):

        def ip_dsfield_in(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=False)
            return self._get_ip_dsfield(rows_filter, 'in')

        rows = list(rows_f())
        return self._host_rows(rows, ip_dsfield_in)

    def _tshark_ip_dsfield_out(self, rows_f):

        def ip_dsfield_out(host_rows):
            rows_filter = self._select_mac_direction(host_rows, output=True)
            return self._get_ip_dsfield(rows_filter, 'out')

        rows = list(rows_f())
        return self._host_rows(rows, ip_dsfield_out)

    def _row_protos(self, row):
        row_layers = {layer.split('.')[0] for layer, val in row.items() if '.' in layer and val} - {
            'data', 'eth', 'ip', 'ipv6', '_ws', 'frame'}
        return row_layers.intersection(self.WK_PROTOS), row_layers

    def _tshark_wk_ip_protos(self, rows_f):

        def protos(host_rows):
            wk_protos = set()
            for row in host_rows:
                wk_proto, row_layers = self._row_protos(row)
                if wk_proto:
                    wk_protos.update(wk_proto)
                if row_layers - wk_proto:
                    wk_protos.add('other')
            return {'tshark_wk_ip_proto_%s' % wk_proto: int(wk_proto in wk_protos) for wk_proto in self.WK_PROTOS}

        return self._host_rows(rows_f(), protos)

    def _tshark_vlan_id(self, rows_f):

        def first_vlan_id(host_rows):
            vlan_id = 0
            for row in host_rows:
                vlan_id = row.get('vlan.id', 0)
                if vlan_id:
                    break
            return {'tshark_vlan_id': vlan_id}

        rows = list(rows_f())
        return self._host_rows(rows, first_vlan_id)

    def _tshark_ipx(self, rows_f):

        def first_ipx(host_rows):
            ipx = 0
            for row in host_rows:
                if self._get_proto_eth_type(row) == ETH_TYPE_IPX:
                    ipx = 1
                    break
            return {'tshark_ipx': ipx}

        rows = list(rows_f())
        return self._host_rows(rows, first_ipx)

    def _tshark_both_private_ip(self, rows_f):

        def first_not_both_private_ip(host_rows):
            both_private = 0
            if host_rows:
                both_private = 1
                for row in host_rows:
                    ip_src, ip_dst = self._get_ips(row)
                    if ip_src and ip_dst:
                        if not ip_src.is_private or not ip_dst.is_private:
                            both_private = 0
                            break
            return {'tshark_both_private_ip': both_private}

        rows = list(rows_f())
        return self._host_rows(rows, first_not_both_private_ip)

    def _tshark_ipv4_multicast(self, rows_f):

        def first_ipv4_multicast(host_rows):
            multicast = 0
            if host_rows:
                for row in host_rows:
                    _, ip_dst = self._get_ips(row)
                    if ip_dst and ip_dst.version == 4 and ip_dst.is_multicast:
                        multicast = 1
                        break
            return {'tshark_ipv4_multicast': multicast}

        rows = list(rows_f())
        return self._host_rows(rows, first_ipv4_multicast)

    def _tshark_non_ip(self, rows_f):

        def first_non_ip(host_rows):
            non_ip = 1
            if host_rows:
                non_ip = 0
                for row in host_rows:
                    if self._get_proto_eth_type(row) not in ETH_IP_TYPES:
                        non_ip = 1
                        break
            return {'tshark_non_ip': non_ip}

        rows = list(rows_f())
        return self._host_rows(rows, first_non_ip)

    def _tshark_average_time_delta(self, rows_f):
        return self._calc_time_delta('average_time_delta', rows_f)

    def _tshark_min_time_delta(self, rows_f):
        return self._calc_time_delta('min_time_delta', rows_f)

    def _tshark_max_time_delta(self, rows_f):
        return self._calc_time_delta('max_time_delta', rows_f)

    def _tshark_average_frame_len(self, rows_f):
        return self._calc_framelen('average_frame_len', rows_f)

    def _tshark_min_frame_len(self, rows_f):
        return self._calc_framelen('min_frame_len', rows_f)

    def _tshark_max_frame_len(self, rows_f):
        return self._calc_framelen('max_frame_len', rows_f)

    def _tshark_median_frame_len(self, rows_f):
        return self._calc_framelen('median_frame_len', rows_f)

    def _tshark_variance_frame_len(self, rows_f):
        return self._calc_framelen('variance_frame_len', rows_f)

    def _tshark_25q_frame_len(self, rows_f):
        return self._calc_framelen('25q_frame_len', rows_f)

    def _tshark_75q_frame_len(self, rows_f):
        return self._calc_framelen('75q_frame_len', rows_f)

    # By direction

    def _tshark_min_frame_time_in(self, rows_f):
        rows = list(rows_f())
        return self._calc_tshark_field('min_frame_time_in', 'frame.time_epoch', rows)

    def _tshark_min_frame_time_out(self, rows_f):
        rows = list(rows_f())
        return self._calc_tshark_field('min_frame_time_out', 'frame.time_epoch', rows)

    def _tshark_max_frame_time_in(self, rows_f):
        rows = list(rows_f())
        return self._calc_tshark_field('max_frame_time_in', 'frame.time_epoch', rows)

    def _tshark_max_frame_time_out(self, rows_f):
        rows = list(rows_f())
        return self._calc_tshark_field('max_frame_time_out', 'frame.time_epoch', rows)

    def _tshark_count_frame_len_in(self, rows_f):
        return self._calc_framelen('count_frame_len_in', rows_f)

    def _tshark_count_frame_len_out(self, rows_f):
        return self._calc_framelen('count_frame_len_out', rows_f)

    def _tshark_total_frame_len_in(self, rows_f):
        return self._calc_framelen('total_frame_len_in', rows_f)

    def _tshark_total_frame_len_out(self, rows_f):
        return self._calc_framelen('total_frame_len_out', rows_f)

    def _tshark_average_frame_len_in(self, rows_f):
        return self._calc_framelen('average_frame_len_in', rows_f)

    def _tshark_average_frame_len_out(self, rows_f):
        return self._calc_framelen('average_frame_len_out', rows_f)

    def _tshark_25q_frame_len_in(self, rows_f):
        return self._calc_framelen('25q_frame_len_in', rows_f)

    def _tshark_25q_frame_len_out(self, rows_f):
        return self._calc_framelen('25q_frame_len_out', rows_f)

    def _tshark_75q_frame_len_in(self, rows_f):
        return self._calc_framelen('75q_frame_len_in', rows_f)

    def _tshark_75q_frame_len_out(self, rows_f):
        return self._calc_framelen('75q_frame_len_out', rows_f)

    def _tshark_median_frame_len_in(self, rows_f):
        return self._calc_framelen('median_frame_len_in', rows_f)

    def _tshark_median_frame_len_out(self, rows_f):
        return self._calc_framelen('median_frame_len_out', rows_f)

    def _tshark_variance_frame_len_in(self, rows_f):
        return self._calc_framelen('variance_frame_len_in', rows_f)

    def _tshark_variance_frame_len_out(self, rows_f):
        return self._calc_framelen('variance_frame_len_out', rows_f)

    def _tshark_max_frame_len_in(self, rows_f):
        return self._calc_framelen('max_frame_len_in', rows_f)

    def _tshark_max_frame_len_out(self, rows_f):
        return self._calc_framelen('max_frame_len_out', rows_f)

    def _tshark_min_frame_len_in(self, rows_f):
        return self._calc_framelen('min_frame_len_in', rows_f)

    def _tshark_min_frame_len_out(self, rows_f):
        return self._calc_framelen('min_frame_len_out', rows_f)

    def _tshark_min_time_delta_in(self, rows_f):
        return self._calc_time_delta('min_time_delta_in', rows_f)

    def _tshark_min_time_delta_out(self, rows_f):
        return self._calc_time_delta('min_time_delta_out', rows_f)

    def _tshark_25q_time_delta_in(self, rows_f):
        return self._calc_time_delta('25q_time_delta_in', rows_f)

    def _tshark_25q_time_delta_out(self, rows_f):
        return self._calc_time_delta('25q_time_delta_out', rows_f)

    def _tshark_median_time_delta_in(self, rows_f):
        return self._calc_time_delta('median_time_delta_in', rows_f)

    def _tshark_median_time_delta_out(self, rows_f):
        return self._calc_time_delta('median_time_delta_out', rows_f)

    def _tshark_average_time_delta_in(self, rows_f):
        return self._calc_time_delta('average_time_delta_in', rows_f)

    def _tshark_average_time_delta_out(self, rows_f):
        return self._calc_time_delta('average_time_delta_out', rows_f)

    def _tshark_75q_time_delta_in(self, rows_f):
        return self._calc_time_delta('75q_time_delta_in', rows_f)

    def _tshark_75q_time_delta_out(self, rows_f):
        return self._calc_time_delta('75q_time_delta_out', rows_f)

    def _tshark_max_time_delta_in(self, rows_f):
        return self._calc_time_delta('max_time_delta_in', rows_f)

    def _tshark_max_time_delta_out(self, rows_f):
        return self._calc_time_delta('max_time_delta_out', rows_f)

    def _tshark_variance_time_delta_in(self, rows_f):
        return self._calc_time_delta('variance_time_delta_in', rows_f)

    def _tshark_variance_time_delta_out(self, rows_f):
        return self._calc_time_delta('variance_time_delta_out', rows_f)


class Host(HostBase, Features):

    def _row_keys(self, row):
        keys = set()
        for field in ('eth.src', 'eth.dst'):
            val = row.get(field, None)
            if not val:
                continue
            if not self._is_unicast(val):
                continue
            keys.add(val)
        return keys

    def pyshark_ipv4(self, rows_f):
        return self._pyshark_ipv4(rows_f)

    def pyshark_ipv6(self, rows_f):
        return self._pyshark_ipv6(rows_f)

    def host_tshark_last_protocols_array(self, rows_f):
        return self._tshark_last_protocols_array(rows_f)

    def host_tshark_ipv4(self, rows_f):
        return self._tshark_ipv4(rows_f)

    def host_tshark_ipv6(self, rows_f):
        return self._tshark_ipv6(rows_f)

    def host_tshark_priv_tcp_ports_in(self, rows_f):
        return self._tshark_priv_tcp_ports_in(rows_f)

    def host_tshark_priv_tcp_ports_out(self, rows_f):
        return self._tshark_priv_tcp_ports_out(rows_f)

    def host_tshark_priv_udp_ports_in(self, rows_f):
        return self._tshark_priv_udp_ports_in(rows_f)

    def host_tshark_priv_udp_ports_out(self, rows_f):
        return self._tshark_priv_udp_ports_out(rows_f)

    def host_tshark_nonpriv_tcp_ports_in(self, rows_f):
        return self._tshark_nonpriv_tcp_ports_in(rows_f)

    def host_tshark_nonpriv_tcp_ports_out(self, rows_f):
        return self._tshark_nonpriv_tcp_ports_out(rows_f)

    def host_tshark_nonpriv_udp_ports_in(self, rows_f):
        return self._tshark_nonpriv_udp_ports_in(rows_f)

    def host_tshark_nonpriv_udp_ports_out(self, rows_f):
        return self._tshark_nonpriv_udp_ports_out(rows_f)

    def host_tshark_tcp_flags_in(self, rows_f):
        return self._tshark_tcp_flags_in(rows_f)

    def host_tshark_tcp_flags_out(self, rows_f):
        return self._tshark_tcp_flags_out(rows_f)

    def host_tshark_ip_flags_in(self, rows_f):
        return self._tshark_ip_flags_in(rows_f)

    def host_tshark_ip_flags_out(self, rows_f):
        return self._tshark_ip_flags_out(rows_f)

    def host_tshark_ip_dsfield_in(self, rows_f):
        return self._tshark_ip_dsfield_in(rows_f)

    def host_tshark_ip_dsfield_out(self, rows_f):
        return self._tshark_ip_dsfield_out(rows_f)

    def host_tshark_wk_ip_protos(self, rows_f):
        return self._tshark_wk_ip_protos(rows_f)

    def host_tshark_vlan_id(self, rows_f):
        return self._tshark_vlan_id(rows_f)

    def host_tshark_ipx(self, rows_f):
        return self._tshark_ipx(rows_f)

    def host_tshark_both_private_ip(self, rows_f):
        return self._tshark_both_private_ip(rows_f)

    def host_tshark_ipv4_multicast(self, rows_f):
        return self._tshark_ipv4_multicast(rows_f)

    def host_tshark_non_ip(self, rows_f):
        return self._tshark_non_ip(rows_f)

    def host_tshark_average_time_delta(self, rows_f):
        return self._tshark_average_time_delta(rows_f)

    def host_tshark_min_time_delta(self, rows_f):
        return self._tshark_min_time_delta(rows_f)

    def host_tshark_max_time_delta(self, rows_f):
        return self._tshark_max_time_delta(rows_f)

    def host_tshark_average_frame_len(self, rows_f):
        return self._tshark_average_frame_len(rows_f)

    def host_tshark_min_frame_len(self, rows_f):
        return self._tshark_min_frame_len(rows_f)

    def host_tshark_max_frame_len(self, rows_f):
        return self._tshark_max_frame_len(rows_f)

    def host_tshark_median_frame_len(self, rows_f):
        return self._tshark_median_frame_len(rows_f)

    def host_tshark_variance_frame_len(self, rows_f):
        return self._tshark_variance_frame_len(rows_f)

    def host_tshark_25q_frame_len(self, rows_f):
        return self._tshark_25q_frame_len(rows_f)

    def host_tshark_75q_frame_len(self, rows_f):
        return self._tshark_75q_frame_len(rows_f)

    def host_tshark_min_frame_time_in(self, rows_f):
        return self._tshark_min_frame_time_in(rows_f)

    def host_tshark_min_frame_time_out(self, rows_f):
        return self._tshark_min_frame_time_out(rows_f)

    def host_tshark_max_frame_time_in(self, rows_f):
        return self._tshark_max_frame_time_in(rows_f)

    def host_tshark_max_frame_time_out(self, rows_f):
        return self._tshark_max_frame_time_out(rows_f)

    def host_tshark_count_frame_len_in(self, rows_f):
        return self._tshark_count_frame_len_in(rows_f)

    def host_tshark_count_frame_len_out(self, rows_f):
        return self._tshark_count_frame_len_out(rows_f)

    def host_tshark_total_frame_len_in(self, rows_f):
        return self._tshark_total_frame_len_in(rows_f)

    def host_tshark_total_frame_len_out(self, rows_f):
        return self._tshark_total_frame_len_out(rows_f)

    def host_tshark_average_frame_len_in(self, rows_f):
        return self._tshark_average_frame_len_in(rows_f)

    def host_tshark_average_frame_len_out(self, rows_f):
        return self._tshark_average_frame_len_out(rows_f)

    def host_tshark_25q_frame_len_in(self, rows_f):
        return self._tshark_25q_frame_len_in(rows_f)

    def host_tshark_25q_frame_len_out(self, rows_f):
        return self._tshark_25q_frame_len_out(rows_f)

    def host_tshark_75q_frame_len_in(self, rows_f):
        return self._tshark_75q_frame_len_in(rows_f)

    def host_tshark_75q_frame_len_out(self, rows_f):
        return self._tshark_75q_frame_len_out(rows_f)

    def host_tshark_median_frame_len_in(self, rows_f):
        return self._tshark_median_frame_len_in(rows_f)

    def host_tshark_median_frame_len_out(self, rows_f):
        return self._tshark_median_frame_len_out(rows_f)

    def host_tshark_variance_frame_len_in(self, rows_f):
        return self._tshark_variance_frame_len_in(rows_f)

    def host_tshark_variance_frame_len_out(self, rows_f):
        return self._tshark_variance_frame_len_out(rows_f)

    def host_tshark_max_frame_len_in(self, rows_f):
        return self._tshark_max_frame_len_in(rows_f)

    def host_tshark_max_frame_len_out(self, rows_f):
        return self._tshark_max_frame_len_out(rows_f)

    def host_tshark_min_frame_len_in(self, rows_f):
        return self._tshark_min_frame_len_in(rows_f)

    def host_tshark_min_frame_len_out(self, rows_f):
        return self._tshark_min_frame_len_out(rows_f)

    def host_tshark_min_time_delta_in(self, rows_f):
        return self._tshark_min_time_delta_in(rows_f)

    def host_tshark_min_time_delta_out(self, rows_f):
        return self._tshark_min_time_delta_out(rows_f)

    def host_tshark_25q_time_delta_in(self, rows_f):
        return self._tshark_25q_time_delta_in(rows_f)

    def host_tshark_25q_time_delta_out(self, rows_f):
        return self._tshark_25q_time_delta_out(rows_f)

    def host_tshark_median_time_delta_in(self, rows_f):
        return self._tshark_median_time_delta_in(rows_f)

    def host_tshark_median_time_delta_out(self, rows_f):
        return self._tshark_median_time_delta_out(rows_f)

    def host_tshark_average_time_delta_in(self, rows_f):
        return self._tshark_average_time_delta_in(rows_f)

    def host_tshark_average_time_delta_out(self, rows_f):
        return self._tshark_average_time_delta_out(rows_f)

    def host_tshark_75q_time_delta_in(self, rows_f):
        return self._tshark_75q_time_delta_in(rows_f)

    def host_tshark_75q_time_delta_out(self, rows_f):
        return self._tshark_75q_time_delta_out(rows_f)

    def host_tshark_max_time_delta_in(self, rows_f):
        return self._tshark_max_time_delta_in(rows_f)

    def host_tshark_max_time_delta_out(self, rows_f):
        return self._tshark_max_time_delta_out(rows_f)

    def host_tshark_variance_time_delta_in(self, rows_f):
        return self._tshark_variance_time_delta_in(rows_f)

    def host_tshark_variance_time_delta_out(self, rows_f):
        return self._tshark_variance_time_delta_out(rows_f)


class SessionHost(HostBase, Features):

    def _row_keys(self, row):
        eth_src = row.get('eth.src', None)
        eth_dst = row.get('eth.dst', None)
        ip_src, ip_dst = self._get_ips(row)
        wk_proto, _ = self._row_protos(row)
        ip_proto = wk_proto.intersection({'tcp', 'udp'})
        if ip_proto:
            ip_proto = list(ip_proto)[0]
        else:
            ip_proto = None
        ip_srcport = None
        ip_dstport = None
        if ip_proto:
            ip_srcport, ip_dstport = self._get_ip_proto_ports(row, ip_proto)
        if eth_dst and self._is_unicast(eth_dst):
            return {
                (eth_src, ip_proto, ip_src, ip_srcport, eth_dst, ip_dst, ip_dstport),
                (eth_dst, ip_proto, ip_dst, ip_dstport, eth_src, ip_src, ip_srcport),
            }
        return {
            (eth_src, ip_proto, ip_src, ip_srcport, eth_dst, ip_dst, ip_dstport)}

    def _host_rows(self, rows, host_func, all_rows=None):
        newrows = []
        for host_key, host_rows in self._partition_rows_by_field_vals(rows, all_rows).items():
            # eth_src only.
            host_key = host_key[0]
            host_func_results = host_func(host_rows)
            host_func_results.update({'host_key': host_key})
            newrows.append(host_func_results)
        return newrows

    def sessionhost_tshark_last_protocols_array(self, rows_f):
        return self._tshark_last_protocols_array(rows_f)

    def sessionhost_tshark_ipv4(self, rows_f):
        return self._tshark_ipv4(rows_f)

    def sessionhost_tshark_ipv6(self, rows_f):
        return self._tshark_ipv6(rows_f)

    def sessionhost_tshark_priv_tcp_ports_in(self, rows_f):
        return self._tshark_priv_tcp_ports_in(rows_f)

    def sessionhost_tshark_priv_tcp_ports_out(self, rows_f):
        return self._tshark_priv_tcp_ports_out(rows_f)

    def sessionhost_tshark_priv_udp_ports_in(self, rows_f):
        return self._tshark_priv_udp_ports_in(rows_f)

    def sessionhost_tshark_priv_udp_ports_out(self, rows_f):
        return self._tshark_priv_udp_ports_out(rows_f)

    def sessionhost_tshark_nonpriv_tcp_ports_in(self, rows_f):
        return self._tshark_nonpriv_tcp_ports_in(rows_f)

    def sessionhost_tshark_nonpriv_tcp_ports_out(self, rows_f):
        return self._tshark_nonpriv_tcp_ports_out(rows_f)

    def sessionhost_tshark_nonpriv_udp_ports_in(self, rows_f):
        return self._tshark_nonpriv_udp_ports_in(rows_f)

    def sessionhost_tshark_nonpriv_udp_ports_out(self, rows_f):
        return self._tshark_nonpriv_udp_ports_out(rows_f)

    def sessionhost_tshark_tcp_flags_in(self, rows_f):
        return self._tshark_tcp_flags_in(rows_f)

    def sessionhost_tshark_tcp_flags_out(self, rows_f):
        return self._tshark_tcp_flags_out(rows_f)

    def sessionhost_tshark_ip_flags_in(self, rows_f):
        return self._tshark_ip_flags_in(rows_f)

    def sessionhost_tshark_ip_flags_out(self, rows_f):
        return self._tshark_ip_flags_out(rows_f)

    def sessionhost_tshark_ip_dsfield_in(self, rows_f):
        return self._tshark_ip_dsfield_in(rows_f)

    def sessionhost_tshark_ip_dsfield_out(self, rows_f):
        return self._tshark_ip_dsfield_out(rows_f)

    def sessionhost_tshark_wk_ip_protos(self, rows_f):
        return self._tshark_wk_ip_protos(rows_f)

    def sessionhost_tshark_vlan_id(self, rows_f):
        return self._tshark_vlan_id(rows_f)

    def sessionhost_tshark_ipx(self, rows_f):
        return self._tshark_ipx(rows_f)

    def sessionhost_tshark_both_private_ip(self, rows_f):
        return self._tshark_both_private_ip(rows_f)

    def sessionhost_tshark_ipv4_multicast(self, rows_f):
        return self._tshark_ipv4_multicast(rows_f)

    def sessionhost_tshark_non_ip(self, rows_f):
        return self._tshark_non_ip(rows_f)

    def sessionhost_tshark_average_time_delta(self, rows_f):
        return self._tshark_average_time_delta(rows_f)

    def sessionhost_tshark_min_time_delta(self, rows_f):
        return self._tshark_min_time_delta(rows_f)

    def sessionhost_tshark_max_time_delta(self, rows_f):
        return self._tshark_max_time_delta(rows_f)

    def sessionhost_tshark_average_frame_len(self, rows_f):
        return self._tshark_average_frame_len(rows_f)

    def sessionhost_tshark_min_frame_len(self, rows_f):
        return self._tshark_min_frame_len(rows_f)

    def sessionhost_tshark_max_frame_len(self, rows_f):
        return self._tshark_max_frame_len(rows_f)

    def sessionhost_tshark_median_frame_len(self, rows_f):
        return self._tshark_median_frame_len(rows_f)

    def sessionhost_tshark_variance_frame_len(self, rows_f):
        return self._tshark_variance_frame_len(rows_f)

    def sessionhost_tshark_25q_frame_len(self, rows_f):
        return self._tshark_25q_frame_len(rows_f)

    def sessionhost_tshark_75q_frame_len(self, rows_f):
        return self._tshark_75q_frame_len(rows_f)

    def sessionhost_tshark_min_frame_time_in(self, rows_f):
        return self._tshark_min_frame_time_in(rows_f)

    def sessionhost_tshark_min_frame_time_out(self, rows_f):
        return self._tshark_min_frame_time_out(rows_f)

    def sessionhost_tshark_max_frame_time_in(self, rows_f):
        return self._tshark_max_frame_time_in(rows_f)

    def sessionhost_tshark_max_frame_time_out(self, rows_f):
        return self._tshark_max_frame_time_out(rows_f)

    def sessionhost_tshark_count_frame_len_in(self, rows_f):
        return self._tshark_count_frame_len_in(rows_f)

    def sessionhost_tshark_count_frame_len_out(self, rows_f):
        return self._tshark_count_frame_len_out(rows_f)

    def sessionhost_tshark_total_frame_len_in(self, rows_f):
        return self._tshark_total_frame_len_in(rows_f)

    def sessionhost_tshark_total_frame_len_out(self, rows_f):
        return self._tshark_total_frame_len_out(rows_f)

    def sessionhost_tshark_average_frame_len_in(self, rows_f):
        return self._tshark_average_frame_len_in(rows_f)

    def sessionhost_tshark_average_frame_len_out(self, rows_f):
        return self._tshark_average_frame_len_out(rows_f)

    def sessionhost_tshark_25q_frame_len_in(self, rows_f):
        return self._tshark_25q_frame_len_in(rows_f)

    def sessionhost_tshark_25q_frame_len_out(self, rows_f):
        return self._tshark_25q_frame_len_out(rows_f)

    def sessionhost_tshark_75q_frame_len_in(self, rows_f):
        return self._tshark_75q_frame_len_in(rows_f)

    def sessionhost_tshark_75q_frame_len_out(self, rows_f):
        return self._tshark_75q_frame_len_out(rows_f)

    def sessionhost_tshark_median_frame_len_in(self, rows_f):
        return self._tshark_median_frame_len_in(rows_f)

    def sessionhost_tshark_median_frame_len_out(self, rows_f):
        return self._tshark_median_frame_len_out(rows_f)

    def sessionhost_tshark_variance_frame_len_in(self, rows_f):
        return self._tshark_variance_frame_len_in(rows_f)

    def sessionhost_tshark_variance_frame_len_out(self, rows_f):
        return self._tshark_variance_frame_len_out(rows_f)

    def sessionhost_tshark_max_frame_len_in(self, rows_f):
        return self._tshark_max_frame_len_in(rows_f)

    def sessionhost_tshark_max_frame_len_out(self, rows_f):
        return self._tshark_max_frame_len_out(rows_f)

    def sessionhost_tshark_min_frame_len_in(self, rows_f):
        return self._tshark_min_frame_len_in(rows_f)

    def sessionhost_tshark_min_frame_len_out(self, rows_f):
        return self._tshark_min_frame_len_out(rows_f)

    def sessionhost_tshark_min_time_delta_in(self, rows_f):
        return self._tshark_min_time_delta_in(rows_f)

    def sessionhost_tshark_min_time_delta_out(self, rows_f):
        return self._tshark_min_time_delta_out(rows_f)

    def sessionhost_tshark_25q_time_delta_in(self, rows_f):
        return self._tshark_25q_time_delta_in(rows_f)

    def sessionhost_tshark_25q_time_delta_out(self, rows_f):
        return self._tshark_25q_time_delta_out(rows_f)

    def sessionhost_tshark_median_time_delta_in(self, rows_f):
        return self._tshark_median_time_delta_in(rows_f)

    def sessionhost_tshark_median_time_delta_out(self, rows_f):
        return self._tshark_median_time_delta_out(rows_f)

    def sessionhost_tshark_average_time_delta_in(self, rows_f):
        return self._tshark_average_time_delta_in(rows_f)

    def sessionhost_tshark_average_time_delta_out(self, rows_f):
        return self._tshark_average_time_delta_out(rows_f)

    def sessionhost_tshark_75q_time_delta_in(self, rows_f):
        return self._tshark_75q_time_delta_in(rows_f)

    def sessionhost_tshark_75q_time_delta_out(self, rows_f):
        return self._tshark_75q_time_delta_out(rows_f)

    def sessionhost_tshark_max_time_delta_in(self, rows_f):
        return self._tshark_max_time_delta_in(rows_f)

    def sessionhost_tshark_max_time_delta_out(self, rows_f):
        return self._tshark_max_time_delta_out(rows_f)

    def sessionhost_tshark_variance_time_delta_in(self, rows_f):
        return self._tshark_variance_time_delta_in(rows_f)

    def sessionhost_tshark_variance_time_delta_out(self, rows_f):
        return self._tshark_variance_time_delta_out(rows_f)
