import argparse
import logging
import os

from networkml import __version__
from networkml.algorithms.host_footprint import HostFootprint
from networkml.featurizers.csv_to_features import CSVToFeatures
from networkml.helpers.results_output import ResultsOutput
from networkml.parsers.pcap_to_csv import PCAPToCSV


class NetworkML:

    def __init__(self, raw_args=None):
        self.logger = logging.getLogger(__name__)
        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}

        # TODO: migrate stage-specific flags here.
        self.stage_args = {
            'parser': {},
            'featurizer': {
                'srcmacid': {'help': 'attempt to detect canonical source MAC and featurize only that MAC', 'action': 'store_true'},
                'no-srcmacid': {'help': 'featurize all MACs', 'action': 'store_true'},
            },
            'algorithm': {
                'trained_model': {'help': 'specify a path to load or save trained model'},
                'label_encoder': {'help': 'specify a path to load or save label encoder'},
                'scaler': {'help': 'specify a path to load or save scaler'},
                'kfolds': {'help': 'specify number of folds for k-fold cross validation'},
                'eval_data': {'help': 'path to eval CSV file, if training'},
                'train_unknown': {'help': 'Train on unknown roles'},
                'list':{'choices':['features'],
                        'default':None,
                        'help':'list information contained within model defined by --trained_model'
                        }
            },
        }
        parsed_args = self.parse_args(raw_args=raw_args)
        self.in_path = parsed_args.path
        self.algorithm = parsed_args.algorithm
        self.engine = parsed_args.engine
        self.first_stage = parsed_args.first_stage
        self.final_stage = parsed_args.final_stage
        self.groups = parsed_args.groups
        self.gzip_opt = parsed_args.gzip
        self.level = parsed_args.level
        self.operation = parsed_args.operation
        self.output = parsed_args.output
        self.threads = parsed_args.threads
        self.list = parsed_args.list
        self.log_level = parsed_args.verbose
        for args in self.stage_args.values():
            for arg in args:
                val = getattr(parsed_args, arg, None)
                if val is not None:
                    setattr(self, arg, val)
        logging.basicConfig(level=log_levels[self.log_level])
        self.main()

    def parse_args(self, raw_args=None):
        parser = argparse.ArgumentParser(description='networkml %s' % __version__)
        parser.add_argument('path', help='path to a single pcap file, or a directory of pcaps to parse', default='/pcaps')
        parser.add_argument('--algorithm', '-a', choices=[
                            'host_footprint'], default='host_footprint', help='choose which algorithm to use (default=host_footprint)')
        parser.add_argument('--engine', '-e', choices=['pyshark', 'tshark', 'host'],
                            default='tshark', help='engine to use to process the PCAP file (default=tshark)')
        parser.add_argument('--first_stage', '-f', choices=['parser', 'featurizer', 'algorithm'], default='parser',
                            help='choose which stage to start at, `path` arg is relative to stage (default=parser)')
        parser.add_argument('--final_stage', choices=['parser', 'featurizer', 'algorithm'],
                            default='algorithm', help='choose which stage to finish at (default=algorithm)')
        parser.add_argument('--groups', '-g', default='host',
                            help='groups of comma separated features to use (default=host)')
        parser.add_argument('--gzip', '-z', choices=['input', 'output', 'both'], default='both',
                            help='use gzip between stages, useful when not using all 3 stages (default=both)')
        parser.add_argument('--level', '-l', choices=['packet', 'flow', 'host'],
                            default='packet', help='level to make the output records (default=packet)')
        parser.add_argument('--operation', '-O', choices=['train', 'predict', 'eval'], default='predict',
                            help='choose which operation task to perform, train or predict (default=predict)')
        parser.add_argument('--output', '-o', default=None,
                            help='directory to write out any results files to')
        parser.add_argument('--threads', '-t', default=1, type=int,
                            help='number of async threads to use (default=1)')
        parser.add_argument('--verbose', '-v', choices=[
                            'DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='logging level (default=INFO)')
        for stage, args in self.stage_args.items():
            for arg, arg_parms in args.items():
                arg_help = '%s (%s)' % (arg_parms['help'], stage)
                arg_choices = arg_parms['choices'] if 'choices' in arg_parms else None
                arg_default = arg_parms['default'] if 'default' in arg_parms else None
                action = arg_parms.get('action', None)
                if not arg_choices:
                    parser.add_argument('--' + arg, help=arg_help, default=arg_default, dest=arg, action=action)
                else:
                    parser.add_argument('--' + arg, help=arg_help, choices=arg_choices, default=arg_default, dest=arg, action=action)
        parsed_args = parser.parse_args(raw_args)
        return parsed_args

    def add_opt_args(self, opt_args):
        raw_args = []
        for arg, arg_parms in opt_args.items():
            val = getattr(self, arg, None)
            if val is not None:
                raw_args.append('--' + arg)
                if arg_parms.get('action', None) != 'store_true':
                    raw_args.append(str(val))
        return raw_args

    def run_parser_stage(self, in_path):
        raw_args = self.add_opt_args(self.stage_args['parser'])
        raw_args.extend(['-e', self.engine, '-l', self.level,
            '-o', self.output, '-t', str(self.threads), '-v', self.log_level, in_path])
        instance = PCAPToCSV(raw_args=raw_args)
        return instance.main()

    def run_featurizer_stage(self, in_path):
        raw_args = self.add_opt_args(self.stage_args['featurizer'])
        raw_args.extend(['-c', '-g', self.groups, '-z', self.gzip_opt,
            '-o', self.output, '-t', str(self.threads), '-v', self.log_level, in_path])
        instance = CSVToFeatures(raw_args=raw_args)
        return instance.main()

    def run_algorithm_stage(self, in_path):
        raw_args = self.add_opt_args(self.stage_args['algorithm'])
        raw_args.extend(['-O', self.operation, '-v', self.log_level, in_path])
        instance = HostFootprint(raw_args=raw_args)
        return instance.main()

    def output_results(self, result_json_str, run_complete):
        if run_complete:
            if self.list:
                print(f'{result_json_str}')
            if self.final_stage == 'algorithm' and self.operation == 'predict':
                if self.output and os.path.isdir(self.output):
                    uid = os.getenv('id', 'None')
                    file_path = os.getenv('file_path', self.in_path)
                    results_outputter = ResultsOutput(self.logger, uid, file_path)
                    result_json_file_name = os.path.join(self.output, 'predict.json')
                    results_outputter.output_from_result_json(result_json_str, result_json_file_name)

    def run_stages(self):
        stages = ('parser', 'featurizer', 'algorithm')
        stage_runners = {
            'parser': self.run_parser_stage,
            'featurizer': self.run_featurizer_stage,
            'algorithm': self.run_algorithm_stage}

        try:
            first_stage_index = stages.index(self.first_stage)
            final_stage_index = stages.index(self.final_stage)
        except ValueError:
            self.logger.error('Unknown first/final stage name')
            return

        if first_stage_index > final_stage_index:
            self.logger.error('Invalid first and final stage combination')
            return

        run_schedule = stages[first_stage_index:(final_stage_index+1)]
        result = self.in_path
        self.logger.info(f'running stages: {run_schedule}')

        run_complete = False
        try:
            for stage in run_schedule:
                runner = stage_runners[stage]
                result = runner(result)
            run_complete = True
        except Exception as err:
            self.logger.error(f'Could not run stage: {err}')

        self.output_results(result, run_complete)

    def main(self):
        self.run_stages()
