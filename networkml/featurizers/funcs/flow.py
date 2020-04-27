from networkml.featurizers.features import Features


class Flow(Features):

    def default_tcp_5tuple(self, rows):
        fields = ['ip.src_host', 'ip.dst_host',
                  'tcp.dstport', 'tcp.srcport', 'frame.protocols']
        return self.get_columns(fields, rows)

    def default_udp_5tuple(self, rows):
        fields = ['ip.src_host', 'ip.dst_host',
                  'udp.dstport', 'udp.srcport', 'frame.protocols']
        return self.get_columns(fields, rows)
