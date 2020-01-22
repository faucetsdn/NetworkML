import argparse
import csv
import gzip
import io
import os

from networkml.featurizers.main import Featurizer

# TODO read in csv.gz, type/level input?, function groups to include, specific functions to include, specific functions to exclude

featurizer = Featurizer()
results = featurizer.main({'groups':('default'), 'functions': [('Host', 'transform_ok')]}, 'foo')
print(results)
