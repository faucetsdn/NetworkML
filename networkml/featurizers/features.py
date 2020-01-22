import inspect

class Features():

    def run_func(self, func_name, *args):
        """
        Helper function that will run the <func_name> with <args> for this func
        :param func_name: name of the function to run
        :param args: list of arguments to run with the function
        """
        func = getattr(self, func_name, None)
        if not func:
            return False

        ret = inspect.getargspec(func)
        #subtract one for the "self"
        upper_num_args = len(ret.args) - 1

        if ret.defaults is not None:
            lower_num_args = upper_num_args - len(ret.defaults)
        else:
            lower_num_args = upper_num_args

        actual_args = len(args)

        if actual_args > upper_num_args or actual_args < lower_num_args:
            print("Error: Incorrect number of args")
            return False

        func(*args)
        return True
