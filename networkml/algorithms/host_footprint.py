"""
A class to perform machine learning operations on computer network traffic
"""
import argparse
import json
import logging

import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelBinarizer

class HostFootprint():
    """
    Perform machine learning operations on a host's network traffic

    A class to peform machine learning operations on network traffic
    represented at the host footprint level. "Host footprint" refers to
    a representation of network traffic in which there are statistical
    features that characterize all packets with a particular host as
    the origin or source.
    """


    def __init__(self, model=None, le=None, scaler_fitted=None):
        """
        le: label encoder, i.e. a mapping between integers and roles. This
        is useful for translating between a device's role (represented as a
        categorical variable) and an integer represention, which is needed
        for modeling purposes.
        scaler_fitted: An object used to consistently scale the statistical
        features before training a model or doing inference.
        """
        self.logger = logging.getLogger(__name__)
        self.model = model
        self.le = le
        self.scaler_fitted = scaler_fitted
        self.main()


    @staticmethod
    def parse_args(parser):
        """
        Use python's argparse module to collect command line arguments
        for using this class
        """
        parser.add_argument('path', help='path to a single csv file')
        parser.add_argument('--operation', choices=['train', 'predict'],
                            default='predict',
                            help='choose which operation task to perform, \
                            train or predict (default=predict)')
        parser.add_argument('--output', '-o', default=None,
                            help='path to write out trained model parameters \
                            (required only for train, ignored for predict)')
        parser.add_argument('--verbose', '-v',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                            default='INFO',
                            help='logging level (default=INFO)')
        parsed_args = parser.parse_args()
        return parsed_args


    def train(self):
        """
        This function takes a .csv file of host footprint features--i.e. each
        row is a feature vector for a given host and each column is a feature
        --and trains a model to do business role classification. This function
        returns the trained model. Because the best model is still yet to be
        determined, this method uses only a simple neural network. A future
        version of this function will use a superior model once our research
        group has done experiments with different models and hyperparameter
        optimization.
        """

        # Load data from host footprint .csv
        df = pd.read_csv(self.path)

        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        X = df.drop("filename", axis=1)
        y = df.filename

        # Extract only role name from strings in y feature
        # Y feature is the full filename of the .pcap file
        # but should be only the role name

        # Split full filename on "-" and create a list
        y = y.str.split("-")
        y = y.str[0] # Extract first element of list, the role name

        # Replace string features with dummy (0/1) features
        # This is "one hot encoding"
        # NOTE: Should this check exist? It could lead to the model
        # functioning even when the input data is garbage
        X = self.string_feature_check(X)

        # Normalize X features before training
        scaler = preprocessing.MinMaxScaler()
        self.scaler_fitted = scaler.fit(X)
        X = self.scaler_fitted.transform(X)

        # Convert y into categorical/numerical feature
        self.le = preprocessing.LabelEncoder()
        y = self.le.fit_transform(y)

        # Calculate number of categories to predict
        num_categories = len(self.le.classes_)

        # Instantiate and train model
        clf = MLPClassifier(solver='sgd',
                            hidden_layer_sizes=(64, 32, num_categories),
                            random_state=1999)
        self.model = clf.fit(X, y)


    def string_feature_check(self, X):
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

        # loop through columns in X
        for col in X.columns:

            # Check if the feature's data type is string
            # Object is the datatype pandas uses for storing strings
            if X[col].dtype == "object":

                # log warning if a string column is found
                self.logger.info(f'String object found in column {col}')

                # Expand features into "dummy", i.e. 0/1
                # features
                new_features = pd.get_dummies(X[col])

                # Add new features onto X dataframe
                X = pd.concat([X, new_features], axis=1)

                # Remove original non-expanded feature from X
                X = X.drop(col, axis=1)

        return X


    def predict(self):
        """
        This function takes a csv of features at the host footprint level and
        then makes a role prediction for each row. The output is the top three
        roles.

        OUTPUTS:
        --all_prediction: top three roles for each host and the associated
        probability of each role -- a dictionary
        """

        # Load data from host footprint .csv
        df = pd.read_csv(self.path)

        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        # This drop function should work even if there is no column
        # named filename
        X = df.drop("filename", axis=1)

        # get filenames to match to predictions
        y = df.filename

        # Normalize X features before training
        X = self.scaler_fitted.transform(X) ## Use already fitted scaler

        # Make model predicton - Will return a vector of values
        predictions_rows = self.model.predict_proba(X)

        # Output JSON of top three roles and probabilities for each file
        all_predictions = {}
        for counter, predictions in enumerate(predictions_rows):

            # These operations do NOT create a sorted list
            # NOTE: To change the number of roles for which you want a
            # prediction change the number number in the argpartition code
            ind = np.argpartition(predictions, 3)[-3:] # Index of top 3 roles
            labels = self.le.inverse_transform(ind) # top three role names
            probs = predictions[ind] # probability of top three roles

            # Put labels and probabilities into list
            role_list = [(k, v) for k, v in zip(labels, probs)]

            # Sort role list by probabilities
            role_list_sorted = sorted(role_list, key=lambda x: x[1],
                                      reverse=True)

            # Place roles and probabilities in json
            role_predictions = json.dumps(role_list_sorted)

            # Create dictionary with filename as key and a json of
            # role predictions for that file
            all_predictions[y[counter]] = role_predictions

        return all_predictions


    def string_feature_check(self, X):
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

        # loop through columns in X
        for col in X.columns:

            # Check if the feature's data type is string
            # Object is the datatype pandas uses for storing strings
            if X[col].dtype == "object":

                # log warning if a string column is found
                self.logger.info(f'String object found in column {col}')

                # Expand features into "dummy", i.e. 0/1
                # features
                new_features = pd.get_dummies(X[col])

                # Add new features onto X dataframe
                X = pd.concat([X, new_features], axis=1)

                # Remove original non-expanded feature from X
                X = X.drop(col, axis=1)

        return X


    def main(self):
        """
        Collect and parse command line arguments for using this class
        """

        # Collect command line arguments
        parsed_args = HostFootprint.parse_args(argparse.ArgumentParser())
        self.path = parsed_args.path
        self.out_path = parsed_args.output
        operation = parsed_args.operation
        log_level = parsed_args.verbose

        # Set logging output options
        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])

        # Basic execution logic
        if operation == 'train':
            self.train()
            print(f'{self.model} {self.le} {self.scaler_fitted}')
        elif operation == 'predict':
            # TODO this shouldn't actually train first, need to save/load
            # model instead
            self.train()
            role_prediction = self.predict()
            print(f'{role_prediction}')


if __name__ == "__main__":

    host_footprint = HostFootprint()

