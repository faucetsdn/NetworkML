from networkml.featurizers.features import Features

class Flow(Features):

    def default_ok(self, file_input):
        print(f'running default, ok {file_input}')

    def transform_ok(self, file_input):
        print(f'it is ok {file_input}')
