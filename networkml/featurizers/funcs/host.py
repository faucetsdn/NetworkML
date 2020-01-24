from networkml.featurizers.features import Features

class Host(Features):


    def global_ipv4(self, rows):
        new_rows = [{'IPv4': 0}]
        for row in rows:
            if 'layers' in row and '<IP Layer>' in row['layers']:
                new_rows[0]['IPv4'] = 1
        return new_rows


    def global_ipv6(self, rows):
        new_rows = [{'IPv6': 0}]
        for row in rows:
            if 'layers' in row and '<IP6 Layer>' in row['layers']:
                new_rows[0]['IPv6'] = 1
        return new_rows
