import gzip
import io


def gzip_reader(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'r'), newline='')  # pytype: disable=wrong-arg-types


def gzip_writer(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'w'), newline='', write_through=True)  # pytype: disable=wrong-arg-types
