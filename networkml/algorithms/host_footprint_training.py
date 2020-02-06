import logging

import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.neural_network import MLPClassifier

def train(input_path):
    """
    This function takes a .csv file of host footprint features--i.e. each
    row is a feature vector for a given host and each column is a feature
    --and trains a model to do business role classification. This function
    returns the trained model. Because the best model is still yet to be
    determined, this method uses only a simple neural network. A future
    version of this function will use a superior model once our research
    group has done experiments with different models and hyperparameter
    optimization.

    INPUTS:
    --input_path: the location of the .csv with host footprint features

    OUTPUTS:
    --model: a trained model
    --le: a label encoder to transform predictions into business roles
    --scaler: a scaler used to transform features, needed for predict module
    """

    ## Load data from host footprint .csv
    df = pd.read_csv(input_path)

    ## Split dataframe into X (the input features or predictors)
    ## and y (the target or outcome or dependent variable)
    X = df.drop("filename", axis=1)
    y = df.filename

    ## Extract only role name from strings in y feature
    ## Y feature is the full filename of the .pcap file
    ## but should be only the role name

    y = y.str.split("-") ## Split full filename on "-"
                         ## which creates a list
    y = y.str[0] ## Extract first element of list
                 ## which is the role name

    ## Replace string features with dummy (0/1) features
    ## This is "one hot encoding"
    X = stringFeatureCheck(X)

    ## Normalize X features before training
    scaler = preprocessing.MinMaxScaler()
    scaler_fitted = scaler.fit(X)
    X = scaler_fitted.transform(X)

    ## Convert y into categorical/numerical feature
    le = preprocessing.LabelEncoder()
    y = le.fit_transform(y)

    ## Calculate number of categories to predict
    num_categories = len(le.classes_)

    ## Train model
    clf = MLPClassifier(solver='sgd',
                        hidden_layer_sizes=(64, 32, num_categories),
                        random_state=1999)

    model = clf.fit(X, y)


    ## Returns trained model, label encoder, and scaler
    return model, le, scaler_fitted

def stringFeatureCheck(X):
    """
    This function takes a pandas dataframe that contains the
    features for a model and checks if any of the features are
    strings (or "objects" in the pandas ontology). If any of the
    features are strings, then that feature is expanded into dummy
    features, i.e. a series of 0/1 features for each category within
    that object feature. The function then removes the original feature.

    INPUTS:
    --X: a pandas dataframe with only the training features

    OUPUTS:
    --X: a pandas dataframe expanded with dummy features

    """

    ## loop through columns in X
    for col in X.columns:

        ## Check if the feature's data type is string
        ## Object is the datatype pandas uses for storing strings
        if X[col].dtype == "object":

            ## log warning
            ## TODO: JOHN SPEED NEEDS HELP USING THE PROPER SYNTAX
            #logging.info(f'String object found in column {col}')

            ## Expand features into "dummy", i.e. 0/1
            ## features
            new_features = pd.get_dummies(X[col])

            ## Add new features onto X dataframe
            X = pd.concat([X, new_features], axis=1)

            ## Remove original non-expanded feature from X
            X = X.drop(col, axis=1)

    return X
