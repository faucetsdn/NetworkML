import gzip
import io

def gzip_reader(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'rb'), newline='')


def gzip_writer(gzip_file):
    return io.TextIOWrapper(gzip.open(gzip_file, 'wb'), newline='', write_through=True)
