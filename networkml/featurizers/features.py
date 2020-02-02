import statistics
from collections import Counter


class Features():

    def run_func(self, func_name, *args):
        """
        Helper function that will run the <func_name> with <args> for this func
        :param func_name: name of the function to run
        :param args: list of arguments to run with the function
        """
        func = getattr(self, func_name, None)
        if not func:
            print("Error: Not a function name that's been defined")
            return False

        results = func(*args)
        return results


    @staticmethod
    def get_columns(fields, rows):
        # Terse but efficient.
        new_rows = [{field: row[field] for field in fields if row.get(field, None)} for row in rows]
        return new_rows


    @staticmethod
    def _stat_row_field(statfunc, field, rows):
        # apply a statistical function, to all rows with a given field.
        try:
            return statfunc([float(row[field]) for row in filter(lambda row: field in row, rows)])
        except (ValueError, statistics.StatisticsError):
            return 0


    @staticmethod
    def _tshark_input_mac(rows):
        '''Infer MAC address of host connected to a port, from pcap.

           Pick the host that most often occurs as both source and destination.
        '''
        eth_srcs = Counter()
        eth_dsts = Counter()
        all_eths = Counter()

        for row in rows:
            eth_src = row.get('eth.src', None)
            if eth_src:
                eth_srcs[eth_src] += 1
                all_eths[eth_src] += 1
            eth_dst = row.get('eth.dst', None)
            if eth_dst:
                eth_dsts[eth_dst] += 1
                all_eths[eth_dst] += 1

        common_eth = set(eth_srcs).union(eth_dsts)
        if len(common_eth) > 1:
            common_count = [(eth, all_eths[eth]) for eth in common_eth]
            max_eth = sorted(common_count, key=lambda x: x[1])[-1][0]
            return max_eth
        return None


    def _select_mac_direction(self, rows, output=True):
        '''Return filter expression selecting input or output rows.'''
        src_mac = self._tshark_input_mac(rows)
        # Select all if can't infer direction.
        if src_mac is None:
            return rows
        if output:
            # Select all rows where traffic originated by inferred source MAC
            return filter(lambda row: row.get('eth.src', None) == src_mac, rows)
        # Select all rows where traffic not originated by inferred source MAC.
        return filter(lambda row: row.get('eth.src', None) != src_mac, rows)


    @staticmethod
    def _tshark_ipversions(rows):
        return {int(row['ip.version']) for row in rows if row.get('ip.version', None)}


    @staticmethod
    def _pyshark_row_layers(rows):
        return filter(lambda row: 'layers' in row, rows)
