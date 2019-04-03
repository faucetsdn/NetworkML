'''
Contains utilities required for parsing pcaps into model training features
'''
import json
import logging
import os

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score

from networkml.parsers.pcap.featurizer import extract_features
from networkml.parsers.pcap.pcap_utils import get_source
from networkml.parsers.pcap.reader import sessionizer


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__.split(os.path.sep)[-1])


def get_labels(labels_file, model_labels=None):
    '''
    Reads the label assignments json from the labels file, and if the model's
    labels are provided, does a match comparison of the two sets.

    Args:
        labels_file: path to the labels_assignment folder
        model_labels: the array of labels as read in from the model file
    Returns:
        label_assignments: an array of all the labels to be evaluated
    '''
    label_assignments = []
    with open(labels_file) as handle:
        label_assignments = json.load(handle)
    if not label_assignments:
        return None

    if model_labels:
        mismatch_ct = 0
        for name in label_assignments:
            label = label_assignments[name]
            if label not in model_labels:
                logger.warn('Label "'+label +
                            '" was not accounted for in this model.')
                mismatch_ct += 1
        if mismatch_ct > 0:
            logger.warn('A total of '+str(mismatch_ct) +
                        ' labels not covered by this model.')
    return label_assignments


def get_true_label(name, label_dict):
    '''
    Reads in a filename, extracts the label, and checks the dictionary
    for the true label, or labels it as Unknown.

    Args:
        name: filename
        label_dict: json of name to label, as specified in the labels file
    Returns:
        A tuple of the name and its matching label, or Unknown if not found
    '''
    key = os.path.split(name)[1].split('-')[0]
    if key in label_dict:
        return (key, label_dict[key])
    else:
        return (key, 'Unknown')


def get_pcap_paths(data_dir):
    '''
    Gets all the pcaps in the provided data directory

    Args:
        data_dir: directory of pcap files
    Returns:
        pcaps: the array of all the pcaps in the directory
    '''
    pcaps = []
    for dirpath, _, filenames in os.walk(data_dir):
        for filename in filenames:
            if os.path.splitext(filename)[1] == '.pcap':
                pcaps.append(os.path.join(dirpath, filename))
    return pcaps


def read_data(data_dir, duration=None, labels=None):
    '''
    Reads all the data in the specified directory and parses it into
    a feature array and a label array.

    Args:
        data_dir: path to the directory that contains the training data
        duration: Time window to compute feature information
        labels: List containing labels to use

    Returns:
        X: numpy 2D array that contains the (high dimensional) features
        y: numpy 1D array that contains the labels for the features in X
        new_labels: Reordered labels used in training
    '''
    try:
        if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        logger.error(
            'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))
    X = []
    y = []
    assigned_labels = []

    label_assignments = get_labels('networkml/configs/label_assignments.json')

    # Get all the files in the directory
    files = get_pcap_paths(data_dir)

    # Go through all the files in the directory
    logger.info('Found {0} pcap files to read.'.format(len(files)))
    count = 0
    for filename in files:
        count += 1
        # Extract the label from the filename
        name, label = get_true_label(filename, label_assignments)
        if label not in assigned_labels:
            assigned_labels.append(label)

        logger.info('Reading {0} ({1} bytes) as {2} ({3}/{4})'.format(
            name, os.path.getsize(filename), label, count, len(files)))
        # Bin the sessions with the specified time window
        binned_sessions = sessionizer(
            filename,
            duration=duration
        )
        # Get the capture source from the binned sessions
        capture_source = get_source(binned_sessions)

        # For each of the session bins, compute the  full feature vectors
        for session_dict in binned_sessions:
            features, _, _, _ = extract_features(
                session_dict,
                capture_source=capture_source
            )

            # Store the feature vector and the labels
            X.append(features)
            y.append(assigned_labels.index(label))

        # Update the labels to reflect the new assignments
        new_labels = assigned_labels + \
            [l for l in labels if l not in assigned_labels]

    return np.stack(X), np.stack(y), new_labels


def select_features(X, y):
    '''
    Select the relevant features from X that are useful for predicting
    the labels in y.

    Args:
        X: numpy 2D array containing input features
        y: numpy 1D array containing labels

    Returns:
        feature_list: List of indices of the selected important features
    '''

    # Get the selection model (stability selection)
    # set the number of trees equal to sqrt(nb_features)
    nb_trees = int(np.sqrt(X.shape[1]))

    selection_forest = ExtraTreesClassifier(nb_trees, random_state=3)
    selection_forest.fit(X, y)

    # Use a cross validated logistic regression to choose the importance
    # threshold at which a feature is included
    step_size = 50
    max_weight = int(max(selection_forest.feature_importances_)) + 1
    trial_thresholds = [
        i/step_size for i in range(1, max_weight*step_size + 1)]
    threshold = 0
    max_score = 0

    for trial in trial_thresholds:
        selected_features = [i
                             for i, score in enumerate(selection_forest.feature_importances_)
                             if score > trial]
        if len(selected_features) > 0:
            X_reduced = X[:, selected_features]
            model = LogisticRegression(
                multi_class='multinomial',
                class_weight='balanced',
                solver='newton-cg',
                random_state=0,
                max_iter=1000
            )
            scores = cross_val_score(model, X_reduced, y, cv=5)
            score = scores.mean()
            if score >= max_score:
                max_score = score
                threshold = trial/step_size

    return [i for i, score in enumerate(selection_forest.feature_importances_)
            if score > threshold]


def whiten_features(X):
    '''
    Fits the whitening transformation for the features X. and returns the
    associated matrix.

    Args:
        X: numpy 2D array containing features

    Returns:
        whitening_transformation: Transformation to whiten features
    '''

    # Use PCA to create a whitening transformation fit to the training set
    whitening_transformation = PCA(whiten=False)
    whitening_transformation.fit(X)

    return whitening_transformation


def choose_regularization(X, y):
    '''
    Chooses a value for the regularization parameter using grid search and
    cross validation.

    Args:
        X: numpy 2D array of model inputs
        y: numpy 1D array of labels

    Returns:
        C: Selected value of the regulatization coefficient
    '''

    # Set up the grid search
    max_C, step_size = 10, 5
    best_score, C = 0, 0
    trial_Cs = [i/step_size for i in range(1, max_C*step_size + 1)]

    # Grid search with cross validation to get C
    for trial in trial_Cs:
        model = LogisticRegression(
            C=trial,
            multi_class='multinomial',
            solver='newton-cg',
            class_weight='balanced',
            random_state=0,
            max_iter=1000
        )
        scores = cross_val_score(model, X, y, cv=10)
        score = scores.mean()
        if score > best_score:
            best_score = score,
            C = trial

    return C
