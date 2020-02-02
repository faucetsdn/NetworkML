import statistics
from numpy import percentile
from networkml.featurizers.features import Features



class Host(Features):

    NAME_TO_STAT = {
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
        assert stat is not None
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
        if 4 in self._pyshark_ipversions(rows):
            return [{'IPv4': 1}]
        return [{'IPv4': 0}]


    def pyshark_ipv6(self, rows):
        if 6 in self._pyshark_ipversions(rows):
            return [{'IPv6': 1}]
        return [{'IPv6': 0}]


    def pyshark_last_highest_layer(self, rows):
        new_rows = [{'highest_layer': ''}]
        for row in self._pyshark_row_layers(rows):
            new_rows[0]['highest_layer'] = row['layers'].split('<')[-1]
        return new_rows


    def pyshark_layers(self, rows):
        new_rows = [{}]
        layers = set()
        for row in self._pyshark_row_layers(rows):
            temp = row['layers'].split('<')[1:]
            layers.update({layer.split(' Layer')[0] for layer in temp})
        new_rows[0].update({layer: 1 for layer in layers})
        return new_rows


    @staticmethod
    def tshark_last_protocols(rows):
        protocols = ''
        for row in rows:
            row_protocols = row.get('frame.protocols', None)
            if row_protocols is not None:
                protocols = row_protocols
        new_rows = [{'Protocols': protocols}]
        return new_rows


    def tshark_ipv4(self, rows):
        if 4 in self._tshark_ipversions(rows):
            return [{'IPv4': 1}]
        return [{'IPv4': 0}]


    def tshark_ipv6(self, rows):
        if 6 in self._tshark_ipversions(rows):
            return [{'IPv6': 1}]
        return [{'IPv6': 0}]

    # Directionless.

    def tshark_avg_time_delta(self, rows):
        return self._calc_tshark_field('average_time_delta', 'frame.time_delta_displayed', rows)


    def tshark_min_time_delta(self, rows):
        return self._calc_tshark_field('min_time_delta', 'frame.time_delta_displayed', rows)


    def tshark_max_time_delta(self, rows):
        return self._calc_tshark_field('max_time_delta', 'frame.time_delta_displayed', rows)


    def tshark_avg_frame_len(self, rows):
        return self._calc_tshark_field('average_frame_len', 'frame.len', rows)


    def tshark_min_frame_len(self, rows):
        return self._calc_tshark_field('min_frame_len', 'frame.len', rows)


    def tshark_max_frame_len(self, rows):
        return self._calc_tshark_field('max_frame_len', 'frame.len', rows)


    def tshark_median_frame_len(self, rows):
        return self._calc_tshark_field('median_frame_len', 'frame.len', rows)


    def tshark_variance_frame_len(self, rows):
        return self._calc_tshark_field('variance_frame_len', 'frame.len', rows)


    def tshark_25q_frame_len(self, rows):
        return self._calc_tshark_field('25q_frame_len', 'frame.len', rows)


    def tshark_75q_frame_len(self, rows):
        return self._calc_tshark_field('75q_frame_len', 'frame.len', rows)

    # By direction

    def tshark_total_frame_len_in(self, rows):
        return self._calc_tshark_field('total_frame_len_in', 'frame.len', rows)


    def tshark_total_frame_len_out(self, rows):
        return self._calc_tshark_field('total_frame_len_out', 'frame.len', rows)


    def tshark_avg_frame_len_in(self, rows):
        return self._calc_tshark_field('average_frame_len_in', 'frame.len', rows)


    def tshark_avg_frame_len_out(self, rows):
        return self._calc_tshark_field('average_frame_len_out', 'frame.len', rows)


    def tshark_25q_frame_len_in(self, rows):
        return self._calc_tshark_field('25q_frame_len_in', 'frame.len', rows)


    def tshark_25q_frame_len_out(self, rows):
        return self._calc_tshark_field('25q_frame_len_out', 'frame.len', rows)


    def tshark_75q_frame_len_in(self, rows):
        return self._calc_tshark_field('75q_frame_len_in', 'frame.len', rows)


    def tshark_75q_frame_len_out(self, rows):
        return self._calc_tshark_field('75q_frame_len_out', 'frame.len', rows)


    def tshark_median_frame_len_in(self, rows):
        return self._calc_tshark_field('median_frame_len_in', 'frame.len', rows)


    def tshark_median_frame_len_out(self, rows):
        return self._calc_tshark_field('median_frame_len_out', 'frame.len', rows)


    def tshark_variance_frame_len_in(self, rows):
        return self._calc_tshark_field('variance_frame_len_in', 'frame.len', rows)


    def tshark_variance_frame_len_out(self, rows):
        return self._calc_tshark_field('variance_frame_len_out', 'frame.len', rows)


    def tshark_max_frame_len_in(self, rows):
        return self._calc_tshark_field('max_frame_len_in', 'frame.len', rows)


    def tshark_max_frame_len_out(self, rows):
        return self._calc_tshark_field('max_frame_len_out', 'frame.len', rows)


    def tshark_min_frame_len_in(self, rows):
        return self._calc_tshark_field('min_frame_len_in', 'frame.len', rows)


    def tshark_min_frame_len_out(self, rows):
        return self._calc_tshark_field('min_frame_len_out', 'frame.len', rows)
