import copy
import inspect
import os
import sys
import time

from networkml.featurizers.features import Features

# TODO move print statements to logging


class Featurizer():

    def import_class(self, path, classes):
        """
        Imports classs from an external directory at runtime. Imported functions will be added
        to classes
        :param path: path where the modules reside
        :param classes: existing class instances
        :return list of newly add class instances
        """
        # make sure path exists
        if os.path.isdir(path) is False:
            print('Error: path {} does not exist'.format(path))
            return classes

        # add the path to the PYTHONPATH
        sys.path.append(path)

        # acquire list of files in the path
        mod_list = os.listdir(path)

        for f in mod_list:

            # continue if it is not a python file
            if f[-3:] != '.py':
                continue

            # get module name by removing extension
            mod_name = os.path.basename(f)[:-3]

            # import the module
            module = __import__(mod_name, locals(), globals())
            for name, cls in inspect.getmembers(module):
                if inspect.isclass(cls) and name != 'Features':
                    instance = cls()
                    if isinstance(instance, Features):
                        # append an instance of the class to classes
                        classes.append((instance, name))
                        print(f'Importing class: {name}')

        return classes

    def run_all_funcs(self, functions_orig, groups_orig, classes_orig, rows_f, parsed_args):
        functions = copy.deepcopy(functions_orig)
        groups = copy.deepcopy(groups_orig)
        classes = copy.deepcopy(classes_orig)
        feature_rows = []
        run_methods = []

        def verify_feature_row(method, feature_row):
            assert isinstance(feature_row, list), 'method %s returned non list: %s' % (
                method, feature_row)
            non_dicts = {x for x in feature_row if not isinstance(x, dict)}
            assert not non_dicts, 'method %s returned something not a dict: %s' % (
                method, non_dicts)

        def run_func(method, func, descr):
            print(f'running {descr}...', end='')
            start_time = time.time()
            feature_row = func()
            elapsed_time = int(time.time() - start_time)
            print(f'{elapsed_time}s')
            verify_feature_row(method, feature_row)
            return feature_row

        # attempt to group methods together based on same field name for more cache hits.
        def method_key(method):
            return ''.join(reversed(method.strip('_in').strip('_out')))

        for f in classes:
            if groups:
                methods = filter(
                    lambda funcname: funcname.startswith(groups), dir(f[0]))
                for method in sorted(methods, key=method_key):
                    feature_rows.append(run_func(method, lambda: f[0].run_func(
                        method, rows_f, parsed_args), f'{f[1]}/{method}'))
                    run_methods.append((f[1], method))

        # run remaining extras
        for function in functions:
            if function not in run_methods:
                for f in classes:
                    if f[1] == function[0]:
                        method = function[1]
                        feature_rows.append(run_func(method, lambda: f[0].run_func(
                            method, rows_f, parsed_args), f'{f[1]}/{function[1]}'))
        return feature_rows

    def main(self, feature_choices, rows, features_path, parsed_args):
        functions = []
        groups = ('default')
        classes = []
        classes = self.import_class(features_path, classes)

        if 'functions' in feature_choices:
            functions = feature_choices['functions']
        if 'groups' in feature_choices:
            groups = feature_choices['groups']

        return self.run_all_funcs(functions, groups, classes, rows, parsed_args)
