import inspect
import os
import sys

class Featurizer():

    def import_class(self, path, classes):
        """
        Imports classs from an external directory at runtime. Imported functions will be added
        to classes
        :param path: path where the modules reside
        :param classes: existing class instances
        :return list of newly add class instances
        """
        #make sure path exists
        if os.path.isdir(path) is False:
            print("Error: path {} does not exist".format(path))
            return classes

        #add the path to the PYTHONPATH
        sys.path.append(path)

        #acquire list of files in the path
        mod_list = os.listdir(path)

        for f in mod_list:

            #continue if it is not a python file
            if f[-3:] != '.py':
                continue

            #get module name by removing extension
            mod_name = os.path.basename(f)[:-3]

            #import the module
            module = __import__(mod_name, locals(), globals())
            for name,cls in inspect.getmembers(module):
                if inspect.isclass(cls) and name != "Features":
                    instance = cls()
                    #append an instance of the class to classes
                    classes.append(instance)
                    print(f'Importing class: {name}')

        return classes

    def main(self, feature_choices, file_input, features_path="./networkml/featurizers/funcs"):
        results = []
        classes = []
        classes = self.import_class(features_path, classes)

        # TODO feature_choices parsing
        for f in classes:
            # TODO transform should be something passed in
            methods = filter(lambda funcname: funcname.startswith('transform_'), dir(f))
            for method in methods:
                print(f'Running method: {f}/{method}')
                results.append(f.run_func(method, file_input))
        return results
