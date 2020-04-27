import functools
import ipaddress

import numpy as np


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
        new_rows = [{field: row[field]
                     for field in fields if row.get(field, None)} for row in rows]
        return new_rows

    @staticmethod
    def _pyshark_row_layers(rows_f):
        return filter(lambda row: 'layers' in row, rows_f())
