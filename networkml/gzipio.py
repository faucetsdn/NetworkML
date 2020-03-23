import gzip
import io

def gzip_reader(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'rt'), newline='')


def gzip_writer(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'wt'), newline='', write_through=True)
