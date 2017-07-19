'''
Trains an instance of the model using data in the specified data directory
'''
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.metrics import f1_score
from sklearn.decomposition import PCA

from sklearn.linear_model import RandomizedLogisticRegression
from sklearn.linear_model import LogisticRegression

from reader import sessionizer
from featurizer import extract_features
from model import LogRegModel

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
        print("Reading", filename)
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
    selection_model = RandomizedLogisticRegression()
    selection_model.fit(X, y)

    # Use a cross validated logistic regression to choose the importance
    # threshold at which a feature is included
    step_size = 50
    max_weight = int(max(selection_model.scores_)) + 1
    trial_thresholds = [i/step_size for i in range(1,max_weight*step_size + 1)]
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
                                       solver='newton-cg'
                                      )
            scores = cross_val_score(model, X_reduced, y, cv=5)
            score = scores.mean()
            if score >= max_score:
                max_score = score
                threshold = trial/step_size

    return [i for i, score in enumerate(selection_model.scores_)
            if score > threshold]

def whiten_features(X):
    '''
    Fits the witening transformation for the features X. and returns the
    associated matrix.

    Args:
        X: numpy 2D array containing features

    Returns:
        whitening_transformation: Transformation to whiten features
    '''

    # Use PCA to create a whitening transformation fit to the training set
    whitening_transformation = PCA(whiten=True)
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
                                    class_weight='balanced'
                                  )
        scores = cross_val_score(model, X, y, cv=10)
        score = scores.mean()
        if score > best_score:
            best_score = score,
            C = trial

    return C

def fit_model(data_dir, duration=None):
    '''
    Fit an instance of the model using the data contained in the specified
    directory.

    Args:
        data_dir: Directory containing the training data
    '''

    print("Reading data")
    # First read the data directory for the features and labels
    X_all, y_all, labels = read_data(data_dir, duration=duration)

    print("Making data splits")
    # Split the data into training, validation, and testing sets
    X_train, X_data, y_train, y_data = train_test_split(
                                                        X_all,
                                                        y_all,
                                                        test_size=0.2,
                                                        random_state=0
                                                       )
    X_vala, X_test, y_vala, y_test = train_test_split(
                                                       X_data,
                                                       y_data,
                                                       test_size=0.5,
                                                       random_state=0
                                                     )

    print("Normalizing features")
    # Mean normalize the features, saving the means and variances
    means = X_train.mean(axis=0)
    stds = X_train.std(axis=0)
    # Set the zero standard deviations to 1
    zero_stds = stds == 0
    stds[zero_stds] = 1
    # Apply the mean normalization transformation to the training data
    X_normed = (X_train - np.expand_dims(means, 0))/np.expand_dims(stds, 0)

    print("Doing feature selection")
    # Select the relevant features from the training set
    feature_list = select_features(X_normed, y_train)
    print(feature_list)
    print("Decorrelating features")
    # Decorrelate the selected features
    whitening_transformation = whiten_features(X_normed[:, feature_list])
    X_input = whitening_transformation.transform(X_normed[:, feature_list])

    print("Selecting C")
    # Use a grid search with cross validation to select the hyperparameter
    C = choose_regularization(X_input, y_train)

    print("Fitting model")
    # Fit the final logistic regression model using this value of C
    model = LogisticRegression(
                                C=C,
                                multi_class='multinomial',
                                solver='newton-cg',
                                class_weight='balanced'
                              )
    model.fit(X_input, y_train)

    X_test_input = (X_test - np.expand_dims(means, 0))/np.expand_dims(stds, 0)
    X_test_input = whitening_transformation.transform(
                                             X_test_input[:, feature_list]
                                                     )
    predictions = model.predict(X_test_input)
    print("F1 score:", f1_score(y_test,predictions,average='weighted'))

    #Construct the full model object
    logregmodel = LogRegModel(
                                duration,
                                means,
                                stds,
                                feature_list,
                                whitening_transformation,
                                model,
                                labels
                             )
    return logregmodel
