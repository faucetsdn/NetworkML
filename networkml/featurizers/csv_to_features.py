import argparse
import csv
import gzip
import io
import os

from networkml.featurizers.main import Featurizer

# TODO read in csv.gz, type/level input?, function groups to include, specific functions to include, specific functions to exclude

featurizer = Featurizer()
featurizer.main([], 'foo')
