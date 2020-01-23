from networkml.featurizers.features import Features

class Flow(Features):

    def default_ok(self, rows):
        return rows

    def transform_ok(self, rows):
        return rows
