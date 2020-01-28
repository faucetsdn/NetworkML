from networkml.featurizers.features import Features


class Host(Features):


    def pyshark_ipv4(self, rows):
        new_rows = [{'IPv4': 0}]
        for row in rows:
            if 'layers' in row and '<IP Layer>' in row['layers']:
                new_rows[0]['IPv4'] = 1
        return new_rows


    def pyshark_ipv6(self, rows):
        new_rows = [{'IPv6': 0}]
        for row in rows:
            if 'layers' in row and '<IPV6 Layer>' in row['layers']:
                new_rows[0]['IPv6'] = 1
        return new_rows


    def pyshark_highest_layer(self, rows):
        new_rows = [{'highest_layer': ''}]
        for row in rows:
            if 'layers' in row:
                new_rows[0]['highest_layer'] = row['layers'].split('<')[-1]#.split(' Layer')[0]
        return new_rows


    def pyshark_layers(self, rows):
        new_rows = [{}]
        # get layers
        layers = []
        for row in rows:
            if 'layers' in row:
                temp = row['layers'].split('<')[1:]
                for t in temp:
                    layers.append(t.split(' Layer')[0])
        for layer in layers:
            new_rows[0][layer] = 1
        return new_rows


    def tshark_ipv4(self, rows):
        new_rows = [{'IPv4': 0}]
        for row in rows:
            if 'ip.version' in row and row['ip.version'] == '4':
                new_rows[0]['IPv4'] = 1
        return new_rows


    def tshark_ipv6(self, rows):
        new_rows = [{'IPv6': 0}]
        for row in rows:
            if 'ip.version' in row and row['ip.version'] == '6':
                new_rows[0]['IPv6'] = 1
        return new_rows


    def tshark_avg_time_delta(self, rows):
        avg_time = 0.0
        new_rows = [{'average_time_delta': avg_time}]
        defective = 0
        for row in rows:
            if 'frame.time_delta_displayed' in row:
                avg_time += float(row['frame.time_delta_displayed'])
            else:
                defective += 1
        avg_time /= len(rows)-defective
        new_rows[0]['average_time_delta'] = avg_time
        return new_rows


    def tshark_protocol(self, rows):
        new_rows = [{'Protocols':''}]
        for row in rows:
            if 'frame.protocols' in row:
                new_rows[0]['Protocols'] = row['frame.protocols']
        return new_rows
