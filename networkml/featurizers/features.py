import statistics


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
    def _tshark_ipversions(rows):
        return {int(row['ip.version']) for row in rows if row.get('ip.version', None)}


    @staticmethod
    def _pyshark_row_layers(rows):
        return filter(lambda row: 'layers' in row, rows)
