from networkml.featurizers.features import Features

class Host(Features):

    def transform_ok(self, file_input):
        print('it is ok')
