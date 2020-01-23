import argparse
import csv
import concurrent.futures
import datetime
import gzip
import humanize
import io
import logging
import numpy as np
import os
import sys
import time

from networkml.featurizers.main import Featurizer


def write_features_to_csv(header, rows, out_file):
    with gzip.open(out_file, 'wb') as f:
        w = csv.DictWriter(io.TextIOWrapper(f, newline='', write_through=True), fieldnames=header)
        w.writeheader()
        w.writerows(rows)

def get_rows(in_file):
    rows = []
    with gzip.open(in_file, 'rb') as f_in:
        reader = csv.DictReader(io.TextIOWrapper(f_in, newline=''))
        for line in reader:
            rows.append(dict(line))
    return rows

def exec_features(features, in_file, out_file, features_path):
    rows = get_rows(in_file)
    featurizer = Featurizer()
    rows = featurizer.main(features, rows, features_path)

    header = set()
    for row in rows:
        for r in row:
            header.update(r.keys())
    header = list(header)

    columns = []
    for row in rows:
        columns.append(np.array(row))
    np_array = np.vstack(columns)

    rows = None
    for method in np_array:
        if rows is None:
            rows = method
        else:
            for i, row in enumerate(method):
                rows[i].update(row)
    rows = rows.tolist()

    if header and rows:
        write_features_to_csv(header, rows, out_file)
    else:
        logger.warning(f'No results based on {features} for {in_file}')

def process_files(threads, features, features_path, in_paths, out_paths):
    num_files = len(in_paths)
    finished_files = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as executor:
        future_to_parse = {executor.submit(exec_features, features, in_paths[i], out_paths[i], features_path): i for i in range(len((in_paths)))}
        for future in concurrent.futures.as_completed(future_to_parse):
            path = future_to_parse[future]
            try:
                finished_files += 1
                future.result()
            except Exception as exc:
                logger.error(f'{path} generated an exception: {exc}')
            else:
                logger.info(f'Finished {finished_files}/{num_files} CSVs.')

def parse_args(parser):
    parser.add_argument('path', help='path to a single gzipped csv file, or a directory of gzipped csvs to parse')
    parser.add_argument('--features_path', '-p', default='./networkml/featurizers/funcs', help='path to featurizer functions (default="./networkml/featurizers/funcs")')
    parser.add_argument('--functions', '-f', default='', help='comma separated list of <class>:<function> to featurize (default=None)')
    parser.add_argument('--groups', '-g', default='default', help='comma separated list of groups of functions to featurize (default=default)')
    parser.add_argument('--logging', '-l', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
    parser.add_argument('--output', '-o', default=None, help='path to write out gzipped csv file or directory for gzipped csv files')
    parser.add_argument('--threads', '-t', default=1, type=int, help='number of async threads to use (default=1)')
    parsed_args = parser.parse_args()
    return parsed_args

def main():
    parsed_args = parse_args(argparse.ArgumentParser())
    in_path = parsed_args.path
    out_path = parsed_args.output
    features_path = parsed_args.features_path
    threads = parsed_args.threads
    log_level = parsed_args.logging
    functions = parsed_args.functions
    groups = parsed_args.groups
    if not groups and not functions:
        logger.warning('No groups or functions were selected, quitting')
        sys.exit()

    log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
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
                if ispcap(pathfile):
                    in_paths.append(os.path.join(root, pathfile))
                    if out_path:
                        out_paths.append(os.path.join(out_path, pathfile) + ".features.gz")
                    else:
                        out_paths.append(os.path.join(root, pathfile) + ".features.gz")
    else:
        in_paths.append(in_path)
        if out_path:
            out_paths.append(out_path)
        else:
            out_paths.append(in_path + ".features.gz")

    process_files(threads, features, features_path, in_paths, out_paths)

    logger.info(f'GZipped CSV file(s) written out to: {out_paths}')

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    start = time.time()
    main()
    end = time.time()
    elapsed = end - start
    human_elapsed = humanize.naturaldelta(datetime.timedelta(seconds=elapsed))
    logging.info(f'Elapsed Time: {elapsed} seconds ({human_elapsed})')
