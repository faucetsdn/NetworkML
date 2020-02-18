import argparse
import logging


class NetworkML():


    def __init__(self):
        self.logger = logging.getLogger(__name__)


    @staticmethod
    def parse_args(parser):
        parser.add_argument('path', help='path to a single pcap file, or a directory of pcaps to parse')
        parser.add_argument('--operation', '-o', choices=['train', 'predict'], default='predict', help='chose which operation task to perform, train or predict (default=predict)')
        parser.add_argument('--algorithm', '-a', choices=['host_footprint'], default='host_footprint', help='chose which algorithm to use (default=host_footprint)')
        parser.add_argument('--engine', '-e', choices=['pyshark', 'tshark', 'host'], default='tshark', help='engine to use to process the PCAP file (default=tshark)')
        parser.add_argument('--level', '-l', choices=['packet', 'flow', 'host'], default='packet', help='level to make the output records (default=packet)')
        parser.add_argument('--threads', '-t', default=1, type=int, help='number of async threads to use (default=1)')
        parser.add_argument('--verbose', '-v', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        parsed_args = parser.parse_args()
        return parsed_args


    def main(self):
        parsed_args = NetworkML.parse_args(argparse.ArgumentParser())
        in_path = parsed_args.path
        engine = parsed_args.engine
        threads = parsed_args.threads
        log_level = parsed_args.verbose
        level = parsed_args.level

        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])


if __name__ == "__main__":
    netml = NetworkML()
