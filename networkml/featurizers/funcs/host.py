import statistics
from numpy import percentile
from networkml.featurizers.features import Features



class Host(Features):


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


    def tshark_avg_time_delta(self, rows):
        new_rows = [
            {'average_time_delta': self._stat_row_field(statistics.mean, 'frame.time_delta_displayed', rows)}]
        return new_rows


    def tshark_min_time_delta(self, rows):
        new_rows = [
            {'min_time_delta': self._stat_row_field(min, 'frame.time_delta_displayed', rows)}]
        return new_rows


    def tshark_max_time_delta(self, rows):
        new_rows = [
            {'max_time_delta': self._stat_row_field(max, 'frame.time_delta_displayed', rows)}]
        return new_rows


    def tshark_avg_frame_len(self, rows):
        new_rows = [
            {'average_frame_len': self._stat_row_field(statistics.mean, 'frame.len', rows)}]
        return new_rows


    def tshark_min_frame_len(self, rows):
        new_rows = [
            {'min_frame_len': self._stat_row_field(min, 'frame.len', rows)}]
        return new_rows


    def tshark_max_frame_len(self, rows):
        new_rows = [
            {'max_frame_len': self._stat_row_field(max, 'frame.len', rows)}]
        return new_rows


    def tshark_median_frame_len(self, rows):
        new_rows = [
            {'median_frame_len': self._stat_row_field(statistics.median, 'frame.len', rows)}]
        return new_rows


    def tshark_variance_frame_len(self, rows):
        new_rows = [
            {'variance_frame_len': self._stat_row_field(statistics.variance, 'frame.len', rows)}]
        return new_rows


    def tshark_25q_frame_len(self, rows):
        new_rows = [
            {'25q_frame_len': self._stat_row_field(lambda x: percentile(x, 25), 'frame.len', rows)}]
        return new_rows


    def tshark_75q_frame_len(self, rows):
        new_rows = [
            {'75q_frame_len': self._stat_row_field(lambda x: percentile(x, 75), 'frame.len', rows)}]
        return new_rows
