import ipaddress
from collections import Counter
import numpy as np
import pandas as pd
import netaddr
from networkml.featurizers.features import Features


MAC_BCAST = netaddr.EUI('FF-FF-FF-FF-FF-FF')
ETH_TYPE_ARP = 0x806
ETH_TYPE_IP = 0x800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_IPX = 0x8137
ETH_IP_TYPES = frozenset((ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_IPV6))
WK_IP_PROTOS = ('tcp', 'udp', 'icmp', 'arp', 'icmpv6', 'gre', 'esp', 'ah')
WK_IP_PROTOS_INDEX = {WK_IP_PROTOS.index(i): i for i in WK_IP_PROTOS}
TCP_UDP_PROTOS = {
  6: 'tcp',
  17: 'udp',
}



class HostBase:

    CALC_COL_NAMES = (
        ('frame.len', 'frame_len'),
        ('frame.time_delta_displayed', 'time_delta'))
    CALC_COL_FUNCS = (
        ('max', lambda x: x.max()),
        ('min', lambda x: x.min()),
        ('count', lambda x: x.count()),
        ('total', lambda x: x.sum()),
        ('average', lambda x: x.mean()),
        ('median', lambda x: x.median()),
        ('variance', lambda x: x.var()),
        ('25q', lambda x: x.quantile(0.25)),
        ('75q', lambda x: x.quantile(0.75)))
    # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
    # TODO: enumerate most common ports from survey (complete indicator matrix too expensive)
    WK_PRIV_TCPUDP_PORTS = frozenset(
        [22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 161, 443, 631])
    WK_NONPRIV_TCPUDP_PORTS = frozenset(
        [1900, 2375, 2376, 5222, 5349, 5353, 5354, 5349, 5357, 6653])
    DROP_PROTOS = {'frame', 'data', 'eth', 'ip', 'ipv6'}

    def _mac(self, mac):
        return netaddr.EUI(int(mac), dialect=netaddr.mac_unix_expanded)

    def _is_unicast(self, mac):
        mac_val = self._mac(mac)
        if mac_val == MAC_BCAST or mac_val.packed[0] & 1:
            return False
        return True

    def _numericintset(self, nums):
        if nums is not None:
            return {int(x) for x in nums if x is not None and not np.isnan(x)}
        return set()

    def _get_ip(self, row, cols):
        ipv = row['ip.version']
        if not pd.isnull(ipv):
            ipv = int(ipv)
            if ipv == 4:
                prefix = 'ip'
            else:
                prefix = 'ipv6'
            for col in cols:
                val = row['.'.join((prefix, col))]
                if not pd.isnull(val):
                    return ipaddress.ip_address(int(val))
        return None

    def _get_src_ip(self, row):
        return self._get_ip(row, ('src', 'src_host'))

    def _get_dst_ip(self, row):
        return self._get_ip(row, ('dst', 'dst_host'))

    def _get_flags(self, mac_df, col_name, decode_map, suffix=None, field_name=None):
        try:
            col = mac_df[col_name]
            unique_flags = self._numericintset(col.unique())
        except KeyError:
            unique_flags = [0]
        flags_counter = Counter()
        for decoded_flag in decode_map.values():  # pytype: disable=attribute-error
            flags_counter[decoded_flag] = 0
        for flags in unique_flags:
            if flags:
                for bit, decoded_flag in decode_map.items():
                    if flags & (2**bit):
                        flags_counter[decoded_flag] += 1
        if field_name is None:
            field_name = col_name.replace('.', '_')
        if suffix is not None:
            return {'tshark_%s_%s_%s' % (
                field_name, decoded_flag, suffix): val
                    for decoded_flag, val in flags_counter.items()}
        return {'tshark_%s_%s' % (
            field_name, decoded_flag): val
                for decoded_flag, val in flags_counter.items()}

    def _tshark_flags(self, suffix, mac_df):
        mac_row_flags = {}
        for func in (
                lambda x, y: self._get_flags(x, 'ip.dsfield', {0: 'ecn0', 1: 'ecn1', 2: 'dscp0', 3: 'dscp1', 4: 'dscp2', 5: 'dscp3', 6: 'dscp4', 7: 'dscp5'}, suffix=y),
                lambda x, y: self._get_flags(x, 'ip.flags', {0: 'fin', 1: 'syn', 2: 'rst', 3: 'psh', 4: 'ack', 5: 'urg', 6: 'ece', 7: 'cwr', 8: 'ns'}, suffix=y),
                lambda x, y: self._get_flags(x, 'tcp.flags', {0: 'fin', 1: 'syn', 2: 'rst', 3: 'psh', 4: 'ack', 5: 'urg', 6: 'ece', 7: 'cwr', 8: 'ns'}, suffix=y),
            ):
            mac_row_flags.update(func(mac_df, suffix))
        return mac_row_flags

    def _lowest_ip_proto_port(self, mac_df, ip_proto):
        src = mac_df['%s.srcport' % ip_proto]
        dst = mac_df['%s.dstport' % ip_proto]
        if src.count() and dst.count():
            return self._numericintset(np.minimum(  # pylint: disable=no-member
                mac_df['%s.srcport' % ip_proto], mac_df['%s.dstport' % ip_proto]).unique())
        return set()

    def _tshark_ports(self, suffix, mac_df):
        mac_row_ports = {}
        def port_priv(port):
            return port < 1024
        for ip_proto in ('udp', 'tcp'):
            lowest_ports = self._lowest_ip_proto_port(mac_df, ip_proto)
            for field_name, ports, wk_ports in (
                    ('priv', {port for port in lowest_ports if port_priv(port)}, self.WK_PRIV_TCPUDP_PORTS),
                    ('nonpriv', {port for port in lowest_ports if not port_priv(port)}, self.WK_NONPRIV_TCPUDP_PORTS),
                ):
                port_flags = {port: int(port in ports) for port in wk_ports}
                port_flags.update({'other': int(bool(lowest_ports) and not ports.issubset(wk_ports))})
                mac_row_ports.update({
                    'tshark_%s_%s_port_%s_%s' % (ip_proto, field_name, port, suffix): present for port, present in port_flags.items()})
        return mac_row_ports

    def _tshark_ipversions(self, mac_df):
        try:
            ip_versions = self._numericintset(mac_df['ip.version'].unique())
        except AttributeError:
            ip_versions = set()
        return {'tshark_ipv%u' % v: int(v in ip_versions) for v in (4, 6)}

    def _tshark_non_ip(self, mac_df):
        try:
            eth_types = self._numericintset(mac_df['eth.type'].unique())
        except AttributeError:
            eth_types = set()
        return {
            'tshark_ipx': int(ETH_TYPE_IPX in eth_types),
            'tshark_nonip': int(bool(eth_types - ETH_IP_TYPES)),
        }

    def _tshark_both_private_ip(self, mac_df):
        try:
            both_private_ip = int(min(self._numericintset(mac_df['_both_private_ip'])) == 1)
        except KeyError:
            both_private_ip = 0
        return {
            'tshark_both_private_ip': both_private_ip,
        }

    def _tshark_ipv4_multicast(self, mac_df):
        try:
            ipv4_multicast = int(max(self._numericintset(mac_df['_ipv4_multicast'])) == 1)
        except KeyError:
            ipv4_multicast = 0
        return {
            'tshark_ipv4_multicast': ipv4_multicast,
        }

    def _tshark_wk_ip_protocol(self, mac_df):
        return self._get_flags(mac_df, '_protos_int', WK_IP_PROTOS_INDEX, suffix=None, field_name='wk_ip_protocol')

    def _tshark_vlan_id(self, mac_df):
        return {
            'tshark_tagged_vlan': int(bool(self._numericintset(mac_df['vlan.id'])))
        }

    def _tshark_unique_ips(self, mac, mac_df):
        return {
            'tshark_unique_srcips': mac_df[mac_df['eth.src']==mac]['_srcip'].nunique(),
            'tshark_unique_dstips': mac_df[mac_df['eth.src']==mac]['_dstip'].nunique(),
        }

    def _calc_cols(self, mac, mac_df):
        mac_row = {}
        for suffix, suffix_func in (
                ('out', lambda x: mac_df[mac_df['eth.src'] == x]),
                ('in', lambda x: mac_df[mac_df['eth.src'] != x]),
            ):
            try:
                suffix_df = suffix_func(mac)
            except KeyError:
                continue
            for col_name, field_name in self.CALC_COL_NAMES:
                col = suffix_df[col_name]
                for calc_name, calc_func in self.CALC_COL_FUNCS:
                    calc_col = 'tshark_%s_%s_%s' % (calc_name, field_name, suffix)
                    val = calc_func(col)
                    if pd.isnull(val):
                        val = 0
                    mac_row.update({calc_col: val})
            for func in (
                    self._tshark_flags,
                    self._tshark_ports,
                ):
                mac_row.update(func(suffix, suffix_df))
        for func in (
                self._tshark_ipversions,
                self._tshark_non_ip,
                self._tshark_both_private_ip,
                self._tshark_ipv4_multicast,
                self._tshark_wk_ip_protocol,
                self._tshark_vlan_id,
            ):
            mac_row.update(func(mac_df))
        mac_row.update(self._tshark_unique_ips(mac, mac_df))
        return mac_row

    def _calc_mac_row(self, mac, mac_df):
        mac_row = {'host_key': str(self._mac(mac))}
        mac_row.update(self._calc_cols(mac, mac_df))
        return mac_row

    def _host_key(self, row):
        raise NotImplementedError

    def _df_ip_flags(self, ip_src, ip_dst):
        both_private_ip = 0
        ipv4_multicast = 0
        if not pd.isnull(ip_src) and not pd.isnull(ip_dst):
            both_private_ip = int(ip_src.is_private and ip_dst.is_private)
            ipv4_multicast = int(ip_dst.version == 4 and ip_dst.is_multicast)
        return (both_private_ip, ipv4_multicast)

    def _df_proto_flags(self, row):
        short_row_keys = set(x.split('.')[0] for x, y in row.items() if not pd.isnull(y) and not x.startswith('_'))
        short_frame_protocols = set(row['frame.protocols'].split(':'))
        all_protos = short_row_keys.union(short_frame_protocols) - self.DROP_PROTOS
        all_protos_int = 0
        for proto in all_protos.intersection(WK_IP_PROTOS):
            index = WK_IP_PROTOS.index(proto)
            all_protos_int += 2**index
        return all_protos_int

    def _tshark_all(self, df, srcmacid):
        print('calculating intermediates', end='', flush=True)
        df['_host_key'], df['_srcip'], df['_dstip'], df['_both_private_ip'], df['_ipv4_multicast'], df['_protos_int'] = zip(*df.apply(self._host_key, axis=1))
        eth_srcs = set(df['eth.src'].unique())
        eth_dsts = set(df['eth.dst'].unique())
        all_unicast_macs = {mac for mac in eth_srcs.union(eth_dsts) if self._is_unicast(mac)}
        host_keys = df['_host_key'].unique()
        host_keys_count = len(host_keys)
        print('.%u MACs, %u sessions' % (len(all_unicast_macs), host_keys_count), end='', flush=True)
        if srcmacid:
            minsrcipmac = df.groupby(['eth.src'])['_srcip'].nunique().idxmin(axis=1)
            assert minsrcipmac in all_unicast_macs
            print('.MAC %s has minimum number of source IPs, selected as canonical source' % self._mac(minsrcipmac), end='', flush=True)
            all_unicast_macs = {minsrcipmac}
        mac_rows = []
        for i, mac in enumerate(all_unicast_macs, start=1):
            mac_df = df[(df['eth.src'] == mac)|(df['eth.dst'] == mac)]
            # If just one MAC, don't need groupby on host key.
            if len(all_unicast_macs) == 1:
                mac_rows.append(self._calc_mac_row(mac, mac_df))
            else:
                s = 0
                for _, key_df in mac_df.groupby('_host_key'):
                    s += 1
                    if s % 100 == 0:
                        print('.MAC %u/%u %.1f%%' % (i, len(all_unicast_macs), s / len(host_keys) * 100), end='', flush=True)
                    mac_rows.append(self._calc_mac_row(mac, key_df))
            print('.MAC %u/%u 100%%.' % (i, len(all_unicast_macs)), end='', flush=True)
        return mac_rows


class Host(HostBase, Features):

    def _host_key(self, row):
        ip_src = self._get_src_ip(row)
        ip_dst = self._get_dst_ip(row)
        both_private_ip, ipv4_multicast = self._df_ip_flags(ip_src, ip_dst)
        protos_int = self._df_proto_flags(row)
        return (0, str(ip_src), str(ip_dst), both_private_ip, ipv4_multicast, protos_int)

    def host_tshark_all(self, df, srcmacid):
        return self._tshark_all(df, srcmacid)


class SessionHost(HostBase, Features):

    def _host_key(self, row):
        eth_src = row['eth.src']
        eth_dst = row['eth.dst']
        ip_src = self._get_src_ip(row)
        ip_dst = self._get_dst_ip(row)
        both_private_ip, ipv4_multicast = self._df_ip_flags(ip_src, ip_dst)
        protos_int = self._df_proto_flags(row)
        if not pd.isnull(ip_src) and not pd.isnull(ip_dst):
            ip_proto = TCP_UDP_PROTOS.get(row['ip.version'], None)
            if ip_proto:
                src_port = row['%s.srcport' % ip_proto]
                dst_port = row['%s.dstport' % ip_proto]
                if ip_src > ip_dst:
                    key = (ip_proto, eth_src, ip_src, src_port, eth_dst, ip_dst, dst_port)
                else:
                    key = (ip_proto, eth_dst, ip_dst, dst_port, eth_src, ip_src, src_port)
            else:
                key = sorted([(eth_src, ip_src), (eth_dst, ip_dst)])
        else:
            key = (row['eth.type'],) + tuple(sorted((eth_src, eth_dst)))
        return (hash('-'.join([str(x) for x in key])), str(ip_src), str(ip_dst), both_private_ip, ipv4_multicast, protos_int)

    def sessionhost_tshark_all(self, df, srcmacid):
        return self._tshark_all(df, srcmacid)
