'''
Contains utilities required for parsing pcaps into model training features
'''
import json
import logging
import os

import numpy as np
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import RandomizedLogisticRegression
from sklearn.model_selection import cross_val_score

try:
    from .reader import sessionizer
    from .pcap_utils import get_source
    from .featurizer import extract_features
except SystemError:  # pragma: no cover
    from reader import sessionizer
    from pcap_utils import get_source
    from featurizer import extract_features

logging.basicConfig(level=logging.INFO)


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
    logger = logging.getLogger(__name__)
    try:
        if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
            logger.setLevel(os.environ['LOG_LEVEL'])
    except Exception as e:
        logger.error(
            'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))
    X = []
    y = []
    assigned_labels = []

    # Get all the files in the directory
    files = []
    with open('opts/label_assignments.json') as handle:
        label_assignments = json.load(handle)

    for dirpath, dirnames, filenames in os.walk(data_dir):
        for file in filenames:
            _, ext = os.path.splitext(file)
            if ext == '.pcap':
                files.append(os.path.join(dirpath, file))
    # Go through all the files in the directory
    logger.info('Found {0} pcap files to read.'.format(len(files)))
    count = 0
    for filename in files:
        count += 1
        # Extract the label from the filename
        name = os.path.split(filename)[1]
        name = name.split('-')[0]
        if name in label_assignments:
            label = label_assignments[name]
            if label not in labels:
                label = 'Unknown'
        else:
            label = 'Unknown'
        if label not in assigned_labels:
            assigned_labels.append(label)

        logger.info('Reading {0} ({1} bytes) as {2} ({3}/{4})'.format(
            filename, os.path.getsize(filename), label, count, len(files)))
        # Bin the sessions with the specified time window
        binned_sessions = sessionizer(
            filename,
            duration=duration
        )
        # Get the capture source from the binned sessions
        capture_source = get_source(binned_sessions)

        # For each of the session bins, compute the  full feature vectors
        for session_dict in binned_sessions:
            features, _, _ = extract_features(
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
    selection_model = RandomizedLogisticRegression(random_state=0)
    selection_model.fit(X, y)

    # Use a cross validated logistic regression to choose the importance
    # threshold at which a feature is included
    step_size = 50
    max_weight = int(max(selection_model.scores_)) + 1
    trial_thresholds = [
        i/step_size for i in range(1, max_weight*step_size + 1)]
    threshold = 0
    max_score = 0
    for trial in trial_thresholds:
        selected_features = [i
                             for i, score in enumerate(selection_model.scores_)
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

    importance = {i: s for i, s in enumerate(selection_model.scores_)}
    return [i for i, score in enumerate(selection_model.scores_)
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
