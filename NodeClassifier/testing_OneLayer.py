'''
Evaluates the performance of a model (second argument) on a directory of
labeled data (first argument).  Results are saved to the path specified by the
third argument.
'''

import sys
import os
import json
import logging
from OneLayer import OneLayerModel

logging.basicConfig(level=logging.INFO)

if __name__ == '__main__':
    logger = logging.getLogger(__name__)

    data_dir = sys.argv[1]
    # Load model from specified path
    logger.info("Loading model")
    model_path = sys.argv[2]
    save_path = sys.argv[3]
    model = OneLayerModel(duration=None, hidden_size=None)
    model.load(model_path)

    # Initialize results dictionary
    results = {}
    results['labels'] = model.labels

    # Get the true label assignments
    logger.info("Getting label assignments")
    with open(os.path.join(data_dir,'label_assignments.json')) as handle:
        label_assignments = json.load(handle)

    # Walk through testing directory and get all the pcaps
    logger.info("Getting pcaps")
    pcaps = []
    for dirpath, dirnames, filenames in os.walk(data_dir):
        for filename in filenames:
            name, extension = os.path.splitext(filename)
            if extension == '.pcap':
                pcaps.append(os.path.join(dirpath,filename))

    # Evaluate the model on each pcap
    for pcap in pcaps:
         # Get the true label
        _, pcap_file = os.path.split(pcap)
        pcap_name = pcap_file.split('-')[0]
        if pcap_name in label_assignments:
            true_label = label_assignments[pcap_name]
        else:
            true_label = 'Unknown'
        single_result = {}
        single_result['label'] = true_label
        logger.info("Reading " + pcap_file + " as " + true_label)
        # Get the internal representations
        representations, _, _, p, _= model.get_representation(pcap, mean=False)
        length = representations.shape[0]
        single_result['aggregate'] = p
        individual_dict = {}
        # Classify each slice
        logger.info("Computing classifications by slice")
        for i in range(length):
            p_r = model.classify_representation(representations[i])
            individual_dict[i] = p_r
        single_result['individual'] = individual_dict
        results[pcap] = single_result

    # Save results to path specified by third argument
    with open(save_path, 'w') as output_file:
        json.dump(results, output_file)
