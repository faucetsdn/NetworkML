from networkml.featurizers.features import Features

class Packet(Features):

    def all(self, rows):
        return rows

    def transform_ok(self, rows):
        return rows
