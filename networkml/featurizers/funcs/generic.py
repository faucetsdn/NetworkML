from networkml.featurizers.features import Features

class Generic(Features):

    def all(self, rows_f):
        return list(rows_f())
