import functools
import ipaddress
import numpy


class Features():

    def __init__(self):
        self.nonempty_generators = set()

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

    @functools.lru_cache()
    def get_float_field(self, field, rows_f):
        vals = numpy.fromiter((float(row[field]) for row in filter(lambda row: field in row, rows_f())), dtype=numpy.float)
        if len(vals):
            self.nonempty_generators.add(rows_f)
            return vals
        # Ensure that we don't get a non empty generator.
        assert rows_f not in self.nonempty_generators, field
        return [0]

    def _stat_row_field(self, statfunc, field, rows_f):
        # apply a statistical function, to all rows with a given field.
        return statfunc(self.get_float_field(field, rows_f))

    @staticmethod
    def _tshark_ipversions(rows):
        return {int(row['ip.version']) for row in rows if row.get('ip.version', None)}

    @staticmethod
    def _pyshark_row_layers(rows_f):
        return filter(lambda row: 'layers' in row, rows_f())

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
