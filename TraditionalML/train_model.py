'''
Trains an instance of the model using data in the specified data directory
'''
import os
import numpy as np

from reader import sessionizer
from featurizer import extract_features

def read_data(data_dir, duration=None):
    '''
    Reads all the data in the specified directory and parses it into
    a feature array and a label array.

    Args:
        data_dir: path to the directory that contains the training data
        duration: Time window to compute feature information

    Returns:
        X: numpy 2D array that contains the (high dimensional) features
        y: numpy 1D array that contains the labels for the features in X
        labels: Ordered list containing the labels used
    '''
    labels = []
    X = []
    y = []

    # Go through all the files in the directory
    for filename in os.listdir(data_dir):
        # Extract the label from the filename
        label = filename.split('_')[0]
        # Add the label to the label list if it is a new one
        if label not in labels:
            labels.append(label)

        # Bin the sessions with the specified time window
        binned_sessions = sessionizer(
                                       os.path.join(data_dir, filename),
                                       duration=duration
                                     )

        # For each of the session bins, compute the  full feature vectors
        for session_dict in binned_sessions:
            features = extract_features(session_dict)
            # Store the feature vector and the labels
            X.append(features)
            y.append(labels.index(label))

    return np.stack(X), np.stack(y), labels

def select_features(X,y):
    '''
    Select the relevant features from X that are useful for predicting
    the labels in y.

    Args:
        X: numpy 2D array containing input features
        y: numpy 1D array containing labels

    Returns:
        feature_list: List of indices of the selected important features
    '''

    pass

def whiten_features(X):
    '''
    Fits the witening transformation for the features X. and returns the
    associated matrix.

    Args:
        X: numpy 2D array containing features

    Returns:
        M: Transformation matrix to whiten features
    '''

    pass

def fit_model(data_dir):
    '''
    Fit an instance of the model using the data contained in the specified
    directory.

    Args:
        data_dir: Directory containing the training data
    '''
    pass
