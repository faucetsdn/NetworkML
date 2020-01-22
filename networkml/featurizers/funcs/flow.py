from networkml.featurizers.features import Features

class Foo(Features):
    def transform_ok(self, file_input):
        print(f'it is ok {file_input}')
