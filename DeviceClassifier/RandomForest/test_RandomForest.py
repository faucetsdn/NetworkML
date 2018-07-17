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
from poseidonml.RandomForestModel import RandomForestModel
import time

logging.basicConfig(level=logging.INFO)

def calc_f1(results, ignore_unknown=False):
    results_by_label = {}
    for file, file_results in results.items():
        if file != 'labels':
            indiv_results = file_results['individual']
            true_label = file_results['label']

            if true_label not in results_by_label:
                if true_label == 'Unknown':
                    if ignore_unknown is False:
                        results_by_label[true_label]  = {'tp':0, 'fp':0, 'fn':0}
                else:
                    results_by_label[true_label]  = {'tp':0, 'fp':0, 'fn':0}

            for i, classification in indiv_results.items():
                class_label = classification[0][0]
                if class_label == 'Unknown' and ignore_unknown is True:
                    class_label = classification[1][0]
                if class_label not in results_by_label:
                    results_by_label[class_label]  = {'tp':0, 'fp':0, 'fn':0}
                if true_label != 'Unknown':
                    if class_label == true_label:
                        results_by_label[true_label]['tp'] += 1
                    if class_label != true_label:
                        results_by_label[true_label]['fn'] += 1
                        results_by_label[class_label]['fp'] += 1
                elif ignore_unknown is False:
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

        if (tp + fn) > 0:
            f1s.append(f1)

        if f1 is not 'NaN':
            if (tp + fn) > 0:
                print("F1 of {} for {}".format(f1, label))

    print("Mean F1: {}".format(np.mean(f1s)))

if __name__ =='__main__':
    logger = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        data_dir = "/pcaps"
    else:
        data_dir = sys.argv[1]
    # Load model from specified path
    if len(sys.argv) > 2:
        load_path = sys.argv[2]
    else:
        load_path = '/models/RandomForestModel.pkl'
    if len(sys.argv) > 3:
        save_path = sys.argv[3]
    else:
        save_path = "models/RandomForestModel.pkl"
    model = RandomForestModel(duration=None, hidden_size=None)
    logger.info("Loading model from %s", load_path)
    model.load(load_path)

    # Initialize results dictionary
    results = {}
    results['labels'] = model.labels

    # Get the true label assignments
    logger.info("Getting label assignments")
    with open('opts/label_assignments.json') as handle:
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
    tick = time.clock()
    file_size = 0
    file_num = 0
    time_slices = 0
    logger.info("processing pcaps")
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
        if representations is not None:
            file_size += os.path.getsize(pcap)
            file_num += 1
            length = representations.shape[0]
            time_slices += length
            single_result['aggregate'] = p
            individual_dict = {}
            # Classify each slice
            logger.info("Computing classifications by slice")
            for i in range(length):
                p_r = model.classify_representation(representations[i])
                individual_dict[i] = p_r
            single_result['individual'] = individual_dict
            results[pcap] = single_result
    tock = time.clock()

    # Save results to path specified by third argument
    if len(sys.argv) >= 4:
        with open(save_path, 'w') as output_file:
            json.dump(results, output_file)
    print('-'*80)
    print("Results with unknowns")
    print('-'*80)
    calc_f1(results)
    print('-'*80)
    print("Results forcing decisions")
    print('-'*80)
    calc_f1(results, ignore_unknown=True)
    print('-'*80)
    print("Analysis statistics")
    print('-'*80)
    elapsed_time = tock -tick
    rate = file_size/(pow(10,6)*elapsed_time)
    print("Evaluated",file_num,"pcaps in", round(elapsed_time,3),"seconds")
    print("Total data:", file_size/pow(10,6),"Mb")
    print("Total capture time:",time_slices/4,"hours")
    print("Data processing rate:", rate, "Mb per second")
    print("time per 15 minute capture", (elapsed_time)/(time_slices),"seconds")
    print('-'*80)
