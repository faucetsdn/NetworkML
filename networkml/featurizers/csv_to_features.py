import argparse
import concurrent.futures
import csv
import logging
import os
import pathlib
from collections import Counter
from collections import defaultdict

import numpy as np

import networkml
from networkml.featurizers.main import Featurizer
from networkml.helpers.gzipio import gzip_reader
from networkml.helpers.gzipio import gzip_writer
from networkml.helpers.pandas_csv_importer import import_csv


class CSVToFeatures():

    def __init__(self, raw_args=None):
        self.logger = logging.getLogger(__name__)
        self.raw_args = raw_args

    @staticmethod
    def get_reader(in_file, use_gzip):
        if use_gzip:
            return gzip_reader(in_file)
        return open(in_file, 'r')

    @staticmethod
    def get_writer(out_file, use_gzip):
        if use_gzip:
            return gzip_writer(out_file)
        return open(out_file, 'w')

    @staticmethod
    def iscsv(pathfile):
        for ext in ('csv', 'gz'):
            if pathfile.endswith(''.join(('.', ext))):
                return True
        return False

    @staticmethod
    def write_features_to_csv(header, rows, out_file, gzip_opt):
        use_gzip = gzip_opt in ['output', 'both']
        with CSVToFeatures.get_writer(out_file, use_gzip) as f_out:
            writer = csv.DictWriter(f_out, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def combine_csvs(out_paths, combined_path, gzip_opt):
        # First determine the field names from the top line of each input file
        fieldnames = {'filename'}
        use_gzip = gzip_opt in ['output', 'both']
        for filename in out_paths:
            with CSVToFeatures.get_reader(filename, use_gzip) as f_in:
                reader = csv.reader(f_in)
                fieldnames.update({header for header in next(reader)})

        # Then copy the data
        with CSVToFeatures.get_writer(combined_path, use_gzip) as f_out:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            for filename in out_paths:
                with CSVToFeatures.get_reader(filename, use_gzip) as f_in:
                    reader = csv.DictReader(f_in)
                    for line in reader:
                        if use_gzip:
                            line['filename'] = filename.split(
                                '/')[-1].split('.features.gz')[0]
                        else:
                            line['filename'] = filename.split(
                                '/')[-1].split('.features')[0]
                        writer.writerow(line)
                CSVToFeatures.cleanup_files([filename])

    @staticmethod
    def cleanup_files(paths):
        for fi in paths:
            if os.path.exists(fi):
                os.remove(fi)

    @staticmethod
    def parse_args(raw_args=None):
        netml_path = list(networkml.__path__)
        parser = argparse.ArgumentParser()
        parser.add_argument(
            'path', help='path to a single gzipped csv file, or a directory of gzipped csvs to parse')
        parser.add_argument('--combined', '-c', action='store_true',
                            help='write out all records from all csvs into a single gzipped csv file')
        parser.add_argument('--features_path', '-p', default=os.path.join(
            netml_path[0], 'featurizers/funcs'), help='path to featurizer functions')
        parser.add_argument('--functions', '-f', default='',
                            help='comma separated list of <class>:<function> to featurize (default=None)')
        parser.add_argument('--groups', '-g', default='host',
                            help='comma separated list of groups of functions to featurize (default=host)')
        parser.add_argument('--gzip', '-z', choices=['input', 'output', 'both', 'neither'],
                            default='both', help='gzip the input/output file, both or neither (default=both)')
        parser.add_argument('--output', '-o', default=None,
                            help='path to write out gzipped csv file or directory for gzipped csv files')
        parser.add_argument('--threads', '-t', default=1, type=int,
                            help='number of async threads to use (default=1)')
        parser.add_argument('--verbose', '-v', choices=[
                            'DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        srcmacid_parser = parser.add_mutually_exclusive_group(required=False)
        srcmacid_parser.add_argument('--srcmacid', dest='srcmacid', action='store_true', help='attempt to detect canonical source MAC and featurize only that MAC')
        srcmacid_parser.add_argument('--no-srcmacid', dest='srcmacid', action='store_false', help='featurize all MACs')
        parser.set_defaults(srcmacid=True)
        parsed_args = parser.parse_args(raw_args)
        return parsed_args

    def exec_features(self, features, in_file, out_file, features_path, gzip_opt, parsed_args):
        in_file_size = os.path.getsize(in_file)
        self.logger.info(f'Importing {in_file} size {in_file_size}')
        df = import_csv(in_file)
        featurizer = Featurizer()
        self.logger.info(f'Featurizing {in_file}')
        rows = featurizer.main(features, df, features_path, parsed_args)

        rowcounts = Counter()
        for row in rows:
            for r in row:
                for header_key in r:
                    rowcounts[header_key] += 1
        rowcompare = defaultdict(set)
        for header_key, header_count in rowcounts.items():
            if header_key != 'host_key':
                rowcompare[header_count].add(header_key)
        assert not len(rowcompare) == 0, 'featurizer returned no results'
        assert len(
            rowcompare) == 1, 'inconsistent featurizer row counts (headers not consistently present in all rows): %s' % rowcompare
        header = list(rowcounts.keys())

        columns = [np.array(row) for row in rows]
        np_array = np.vstack(columns)

        rows = None
        for method in np_array:
            if rows is None:
                rows = method
            else:
                for i, row in enumerate(method):
                    rows[i].update(row)

        if header and rows is not None:
            rows = rows.tolist()
            CSVToFeatures.write_features_to_csv(
                header, rows, out_file, gzip_opt)
        else:
            self.logger.warning(
                f'No results based on {features} for {in_file}')

    def process_files(self, threads, features, features_path, in_paths, out_paths, gzip_opt, parsed_args):
        num_files = len(in_paths)
        failed_paths = []
        finished_files = 0
        # corner case so it works in jupyterlab
        if threads < 2:
            for i in range(len(in_paths)):
                try:
                    finished_files += 1
                    self.exec_features(
                        features, in_paths[i], out_paths[i], features_path, gzip_opt, parsed_args)
                    self.logger.info(
                        f'Finished {in_paths[i]}. {finished_files}/{num_files} CSVs done.')
                except Exception as e:  # pragma: no cover
                    self.logger.error(
                        f'{in_paths[i]} generated an exception: {e}')
                    failed_paths.append(out_paths[i])
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as executor:
                future_to_parse = {executor.submit(
                    self.exec_features, features, in_paths[i], out_paths[i], features_path, gzip_opt, parsed_args): i for i in range(len((in_paths)))}
                for future in concurrent.futures.as_completed(future_to_parse):
                    path = future_to_parse[future]
                    try:
                        finished_files += 1
                        future.result()
                    except Exception as e:  # pragma: no cover
                        self.logger.error(
                            f'{in_paths[path]} generated an exception: {e}')
                        failed_paths.append(out_paths[path])
                    else:
                        self.logger.info(
                            f'Finished {in_paths[path]}. {finished_files}/{num_files} CSVs done.')
        return failed_paths

    def main(self):
        parsed_args = CSVToFeatures.parse_args(raw_args=self.raw_args)
        in_path = parsed_args.path
        out_path = parsed_args.output
        combined = parsed_args.combined
        features_path = parsed_args.features_path
        threads = parsed_args.threads
        log_level = parsed_args.verbose
        functions = parsed_args.functions
        groups = parsed_args.groups
        gzip_opt = parsed_args.gzip

        if not groups and not functions:
            self.logger.warning(
                'No groups or functions were selected, quitting')
            return

        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])

        in_paths = []
        out_paths = []

        # parse out features dict
        groups = tuple(groups.split(','))
        funcs = functions.split(',')
        functions = []
        for function in funcs:
            functions.append(tuple(function.split(':')))
        features = {'groups': groups, 'functions': functions}

        # check if it's a directory or a file
        if os.path.isdir(in_path):
            if out_path:
                pathlib.Path(out_path).mkdir(parents=True, exist_ok=True)
            for root, _, files in os.walk(in_path):
                for pathfile in files:
                    if CSVToFeatures.iscsv(pathfile):
                        in_paths.append(os.path.join(root, pathfile))
                        if out_path:
                            if gzip_opt in ['neither', 'input']:
                                out_paths.append(os.path.join(
                                    out_path, pathfile) + '.features')
                            else:
                                out_paths.append(os.path.join(
                                    out_path, pathfile) + '.features.gz')
                        else:
                            if gzip_opt in ['neither', 'input']:
                                out_paths.append(os.path.join(
                                    root, pathfile) + '.features')
                            else:
                                out_paths.append(os.path.join(
                                    root, pathfile) + '.features.gz')
        else:
            in_paths.append(in_path)
            default_out_path = in_path + '.features.gz'
            if gzip_opt in ['neither', 'input']:
                default_out_path = in_path + '.features'
            if out_path:
                if os.path.isdir(out_path):
                    out_paths.append(os.path.join(out_path, os.path.basename(default_out_path)))
                else:
                    out_paths.append(out_path)
            else:
                out_paths.append(default_out_path)

        failed_paths = self.process_files(
            threads, features, features_path, in_paths, out_paths, gzip_opt, parsed_args)

        for failed_path in failed_paths:  # pragma: no cover
            if failed_path in out_paths:
                out_paths.remove(failed_path)

        if combined and out_paths:
            combined_path = os.path.join(
                os.path.dirname(out_paths[0]), 'combined.csv.gz')
            if gzip_opt in ['input', 'neither']:
                combined_path = combined_path[:-3]
            self.logger.info(
                f'Combining CSVs into a single file: {combined_path}')
            CSVToFeatures.combine_csvs(out_paths, combined_path, gzip_opt)
            return combined_path
        if out_paths:
            self.logger.info(f'GZipped CSV file(s) written out to: {out_paths}')
            return os.path.dirname(out_paths[0])
        else:
            self.logger.error(f'No CSV file(s) written out because the following paths failed: {failed_paths}')
            return


if __name__ == '__main__':  # pragma: no cover
    features = CSVToFeatures()
    features.main()
