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

    def get_columns(self, fields, rows):
        new_rows = []
        for row in rows:
            new_row = {}
            for field in fields:
                if field in row and row[field]:
                    new_row[field] = row[field]
            new_rows.append(new_row)
        return new_rows
