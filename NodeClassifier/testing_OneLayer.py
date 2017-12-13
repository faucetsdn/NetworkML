'''
Evaluates the performance of a model (second argument) on a directory of
labeled data (first argument).  Results are saved to the path specified by the
third argument.
'''

import sys
import os
import json
import logging
import numpy as np
from utils.OneLayer import OneLayerModel

logging.basicConfig(level=logging.INFO)

def calc_f1(results):
    logger = logging.getLogger(__name__)
    results_by_label = {}
    for file, file_results in results.items():
        if file != 'labels':
            indiv_results = file_results['individual']
            true_label = file_results['label']
            if true_label not in results_by_label:
                results_by_label[true_label]  = {'tp':0, 'fp':0, 'fn':0}
            for i, classification in indiv_results.items():
                class_label = classification[0][0]
                if class_label not in results_by_label:
                    results_by_label[class_label]  = {'tp':0, 'fp':0, 'fn':0}
                if class_label == true_label:
                    results_by_label[true_label]['tp'] += 1
                if class_label != true_label:
                    results_by_label[true_label]['fn'] += 1
                    results_by_label[class_label]['fp'] += 1
    f1s = []
    for label in results_by_label:
        tp = results_by_label[label]['tp']
        fp = results_by_label[label]['fp']
        fn = results_by_label[label]['fn']

        try:
            precision = tp/(tp + fp)
            recall = tp/(tp + fn)
        except:
            precision = 0
            recall = 0

        if precision == 0 or recall == 0:
            f1 = 0
        else:
            f1 = 2/(1/precision + 1/recall)
        f1s.append(f1)

        if f1 is not 'NaN':
            logger.info("F1 of {} for {}".format(f1, label))

    logger.info("Mean F1: {}".format(np.mean(f1s)))

if __name__ =='__main__':
    logger = logging.getLogger(__name__)

    data_dir = sys.argv[1]
    # Load model from specified path
    logger.info("Loading model")
    model_path = sys.argv[2]
    if len(sys.argv) >= 4:
        save_path = sys.argv[30]
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
    if len(sys.argv) > 4:
        with open(save_path, 'w') as output_file:
            json.dump(results, output_file)
    print("calculating results")
    calc_f1(results)
