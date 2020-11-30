import datetime
import humanize
import logging
import time


def main():
    from networkml.NetworkML import NetworkML
    start = time.time()
    NetworkML()
    end = time.time()
    elapsed = end - start
    human_elapsed = humanize.naturaldelta(datetime.timedelta(seconds=elapsed))
    logging.info(f'Elapsed Time: {elapsed} seconds ({human_elapsed})')
