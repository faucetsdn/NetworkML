from networkml.featurizers.features import Features

class Foo(Features):
    def transform_ok(self):
        print('it is ok')
