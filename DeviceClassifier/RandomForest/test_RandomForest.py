'''
Evaluates the performance of a model (second argument) on a directory of
labeled data (first argument).  Results are saved to the path specified by the
third argument.
'''
import argparse
import json
import logging
import os
import sys
import time

import numpy as np
import poseidonml.training_utils as utils 
from poseidonml.Model import Model


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__.split(os.path.sep)[-1])



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', '-c', default='opts/config.json',
                        help='model\'s config file')
    parser.add_argument('--pcaps', '-P', default='/pcaps',
                        help='pcap directory to train on (e.g., /pcaps)')
    parser.add_argument('--model', '-r', default='/models/RandomForestModel.pkl',
                        help='path to the RandomForest model (pickle file)')
    parser.add_argument('--save', '-w', default='models/RandomForestModel.pkl',
                        help='path to save the model (pickle file)')
    parser.add_argument('--labels', '-l', default='opts/label_assignments.json',
                        help='path to labels file (default: opts/label_assignments.json)')
    parser.add_argument('--debug', action='store_true', 
                        help='print debug messages, if any')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else: 
        try:
            if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
                logger.setLevel(os.environ['LOG_LEVEL'])
        except Exception as e:
            logger.error(
                'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))

    data_dir = args.pcaps
    # Load model from specified path
    model_path = args.model
    save_path = args.save

    model = Model(duration=None, hidden_size=None, model_type='RandomForest')
    logger.info('Loading model from %s', model_path)
    model.load(model_path)

    # Initialize results dictionary
    results = {}
    results['labels'] = model.labels

    # Get the true label assignments
    logger.info('Getting label assignments')
    label_assignments = utils.get_labels(args.labels, model_labels=model.labels)
    if not label_assignments:
        logger.warn('Could not read label assignments; continuing anyway.')

    # Walk through testing directory and get all the pcaps
    logger.info('Getting pcaps')
    pcaps = utils.get_pcap_paths(data_dir)
    if not pcaps:
        logger.error('No pcaps were found in data directory; exiting.')
        return

    # Evaluate the model on each pcap
    file_size = 0
    file_num = 0
    time_slices = 0
    logger.info('processing pcaps')
    tick = time.clock()
    for pcap in pcaps:
         # Get the true label
        label = utils.get_true_label(pcap, label_assignments)
        single_result = {}
        single_result['label'] = label[1]
        logger.info('Reading ' + label[0] + ' as ' + label[1])
        # Get the internal representations
        representations, _, _, p, _ = model.get_representation(
            pcap, mean=False)
        if representations is not None:
            file_size += os.path.getsize(pcap)
            file_num += 1
            length = representations.shape[0]
            time_slices += length
            single_result['aggregate'] = p
            individual_dict = {}
            # Classify each slice
            logger.info('Computing classifications by slice')
            for i in range(length):
                p_r = model.classify_representation(representations[i])
                individual_dict[i] = p_r
            single_result['individual'] = individual_dict
            results[pcap] = single_result
    tock = time.clock()

    # Save results to path specified by third argument
    with open(save_path, 'w') as output_file:
        json.dump(results, output_file)
    logger.info('-'*80)
    logger.info('Results with unknowns')
    logger.info('-'*80)
    model.calc_f1(results)
    logger.info('-'*80)
    logger.info('Results forcing decisions')
    logger.info('-'*80)
    model.calc_f1(results, ignore_unknown=True)
    logger.info('-'*80)
    logger.info('Analysis statistics')
    logger.info('-'*80)
    elapsed_time = tock - tick
    rate = file_size/(pow(10, 6)*elapsed_time)
    logger.info('Evaluated {0} pcaps in {1} seconds'.format(
        file_num, round(elapsed_time, 3)))
    logger.info('Total data: {0} Mb'.format(file_size/pow(10, 6)))
    logger.info('Total capture time: {0} hours'.format(time_slices/4))
    logger.info('Data processing rate: {0} Mb per second'.format(rate))
    logger.info('time per 15 minute capture {0} seconds'.format(
        (elapsed_time)/(time_slices)))
    logger.info('-'*80)


if __name__ == '__main__':
    main()
