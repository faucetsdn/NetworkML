"""
A class to perform machine learning operations on computer network traffic
"""
import argparse
import json
import logging
import os

import numpy as np
import pandas as pd
import sklearn_json as skljson
from sklearn import preprocessing
from sklearn.model_selection import GridSearchCV
from sklearn.neural_network import MLPClassifier

import networkml


class HostFootprint():
    """
    Perform machine learning operations on a host's network traffic

    A class to peform machine learning operations on network traffic
    represented at the host footprint level. "Host footprint" refers to
    a representation of network traffic in which there are statistical
    features that characterize all packets with a particular host as
    the origin or source.
    """

    def __init__(self, raw_args=None):
        self.logger = logging.getLogger(__name__)
        self.raw_args = raw_args

    @staticmethod
    def serialize_label_encoder(le, path):
        """Serialize label encoder to enable persistence
        without pickling the file. .pkl files are a security
        risk and should be avoided
        Model is saved as a JSON object.
        INPUT:
        --le: the label encoder object (from sklearn) to be saved
        --path: filepath for saving the object
        OUTPUT:
        --Does not return anything
        """
        serialized_le = {
            'classes': le.classes_.tolist(),
        }
        with open(path, 'w') as model_json:
            json.dump(serialized_le, model_json)

    @staticmethod
    def deserialize_label_encoder(path):
        """Deserialize JSON object storing label encoder.
        Label encoder (from sklearn) is re-instantiated
        with proper values.
        INPUT:
        --path: filepath for loading the JSON object
        OUTPUT:
        --le: Returns label encoder (sklearn) object
        """
        with open(path, 'r') as model_json:
            model_dict = json.load(model_json)
        # Instantiate and assign class label
        le = preprocessing.LabelEncoder()
        le.classes_ = np.array(model_dict['classes'])
        return le

    @staticmethod
    def parse_args(raw_args=None):
        """
        Use python's argparse module to collect command line arguments
        for using this class
        """
        netml_path = list(networkml.__path__)
        parser = argparse.ArgumentParser()
        parser.add_argument('path', help='path to a single csv file')
        parser.add_argument('--kfolds', '-k',
                            default=5,
                            help='specify number of folds for k-fold cross validation')
        parser.add_argument('--label_encoder', '-l',
                            default=os.path.join(netml_path[0],
                                                 'trained_models/host_footprint_le.json'),
                            help='specify a path to load or save label encoder')
        parser.add_argument('--operation', '-O', choices=['train', 'predict'],
                            default='predict',
                            help='choose which operation task to perform, \
                            train or predict (default=predict)')
        parser.add_argument('--trained_model', '-t',
                            default=os.path.join(netml_path[0],
                                                 'trained_models/host_footprint.json'),
                            help='specify a path to load or save trained model')
        parser.add_argument('--verbose', '-v',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                            default='INFO',
                            help='logging level (default=INFO)')
        parsed_args = parser.parse_args(raw_args)
        return parsed_args

    def train(self):
        """
        This function takes a .csv file of host footprint features--i.e. each
        row is a feature vector for a given host and each column is a feature
        --and trains a model to do functional role classification. This function
        saves the trained model. Because the best model is still yet to be
        determined, this method uses only a simple neural network. A future
        version of this function will use a superior model once our research
        group has done experiments with different models and hyperparameter
        optimization.
        """

        # Load data from host footprint .csv
        df = pd.read_csv(self.path)
        if 'host_key' in df.columns:
            df = df.drop(columns=['host_key'])
        df = df.fillna(0)

        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        X = df.drop('filename', axis=1)
        y = df.filename

        # Extract only role name from strings in y feature
        # Y feature is the full filename of the .pcap file
        # but should be only the role name

        # Split full filename on "-" and create a list
        y = y.str.split('-')
        y = y.str[0]  # Extract first element of list, the role name

        # Replace string features with dummy (0/1) features
        # This is "one hot encoding"
        X = self.string_feature_check(X)

        # Normalize X features before training
        scaler = preprocessing.StandardScaler()
        scaler_fitted = scaler.fit(X)
        X = scaler_fitted.transform(X)

        # Convert y into categorical/numerical feature
        le = preprocessing.LabelEncoder()
        y = le.fit_transform(y)

        # Save label encoder
        HostFootprint.serialize_label_encoder(le, self.le_path)

        # Instantiate neural network model
        # MLP = multi-layer perceptron
        model = MLPClassifier()

        # Perform grid-search with hyperparameter optimization
        # to find the best model
        parameters = {'hidden_layer_sizes': [(64, 32), (32, 16),
                                             (64, 32, 32),
                                             (64, 32, 32, 16)]}
        clf = GridSearchCV(model, parameters,
                           cv=self.kfolds, n_jobs=-1,
                           scoring='f1_weighted')

        self.logger.info(f'Beginning model training')
        # Find best fitting model from the hyper-parameter
        # optimization process
        self.model = clf.fit(X, y).best_estimator_

        # Save model to JSON
        skljson.to_json(self.model, self.model_path)

    def predict(self):
        """
        This function takes a csv of features at the host footprint level and
        then makes a role prediction for each row. The output is the top three
        roles.

        OUTPUTS:
        --all_predictions: a dict with the filename for a key and a JSON'ified dict
        dict for a value. see sorted_roles_to_json() for a description of
        the value's structure.
        """

        # Load data from host footprint .csv
        df = pd.read_csv(self.path)
        if 'host_key' in df.columns:
            df = df.drop(columns=['host_key'])

        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        # This drop function should work even if there is no column
        # named filename
        X = df.drop('filename', axis=1)

        # Get filenames to match to predictions
        filename = df.filename

        # Normalize X features before predicting
        scaler = preprocessing.StandardScaler()
        scaler_fitted = scaler.fit(X)
        X = scaler_fitted.transform(X)

        # Get label encoder
        le = HostFootprint.deserialize_label_encoder(self.le_path)

        # Load (or deserialize) model from JSON
        self.model = skljson.from_json(self.model_path)

        # Convert coeficients to numpy arrays to enable JSON deserialization
        # This is a hack to compensate for a bug in sklearn_json
        for i, x in enumerate(self.model.coefs_):
            self.model.coefs_[i] = np.array(x)

        self.logger.info(f'Executing model inference')

        # Make model predicton - Will return a vector of values
        predictions_rows = self.model.predict_proba(X)

        # Dict to store top role and list of top roles
        all_predictions = self.get_individual_predictions(
            predictions_rows, le, filename)

        return all_predictions

    def get_individual_predictions(self, predictions_rows, label_encoder, filename):
        """ Return role predictions for given device

        INPUTS:
        --predictions_rows: each device is represented as a row
        --label_encoder: a mapping of device role name to numerical category
        --filename: the filename of the pcap for which a prediction is made

        OUTPUTS:
        --all_predictions: a dict with the filename for a key and a
        JSON'ified dict for a value. see sorted_roles_to_json() for a description
        of the value's structure.
        """

        # Dict to store JSON of top n roles and probabilities per device
        all_predictions = {}

        # Loop thru different devices on which to make prediction
        for counter, predictions in enumerate(predictions_rows):

            # total number of functional roles
            num_roles = len(predictions)

            # programmer's note: the code block below ensures that the top
            # three roles and their probabilities are returned when there
            # are three or more roles present in the model. The code
            # returns two roles if only two roles are present

            # top_n_roles: desired number of roles for results
            # note: the numbers below are not intuitive but are consistent
            # with the logic of argpartition
            top_n_roles = min(2, num_roles-1)
            # Get indices of top n roles
            # note: argpartion does not sort top roles - must be done later
            ind = np.argpartition(predictions,
                                  top_n_roles)[-(top_n_roles+1):]

            # top three role names
            labels = label_encoder.inverse_transform(ind)

            # probability of top three roles
            probs = predictions[ind]

            # Put labels and probabilities into list
            role_list = [(k, v) for k, v in zip(labels, probs)]

            # Sort role list by probabilities
            role_list_sorted = sorted(role_list, key=lambda x: x[1],
                                      reverse=True)

            # Dump to JSON top role and roles-probability list
            predictions_json = self.sorted_roles_to_json(role_list_sorted)

            # Create dictionary with filename as key and a JSON
            # of predictions as value
            all_predictions[filename[counter]] = predictions_json

        return all_predictions

    @staticmethod
    def sorted_roles_to_json(role_list_sorted, threshold=.5):
        """ Converted sorted role-probability list into formatted dict

        This function ensures that the top role returned is Unknown
        if the top role has a probability less than the threshold
        specified in the default input parameter.

        INPUTS:
        --role_list_sorted: a sorted list that associates the top role
        with their probabilities
        --threshold: probability threshold below which the top role
        should be designated as "Unknown"

        OUTPUTS:
        --predictions_json: a JSON encoding of a dict with the top role
        and a sorted role list
        """

        # Probability associated with the most likely role
        top_role_prob = role_list_sorted[0][1]

        # Only use actual top role if probability is greater
        # than designated threshold
        if top_role_prob <= threshold:
            top_role = 'Unknown'
        else:
            top_role = role_list_sorted[0][0]  # Most likely role

        # Create dict to store prediction results
        role_predictions = {}
        role_predictions['top_role'] = top_role
        role_predictions['role_list'] = role_list_sorted

        # Dump to JSON top role and roles-probability list
        predictions_json = json.dumps(role_predictions)

        return predictions_json

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
            if X[col].dtype == 'object':

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
        parsed_args = HostFootprint.parse_args(raw_args=self.raw_args)
        self.path = parsed_args.path
        self.model_path = parsed_args.trained_model
        self.le_path = parsed_args.label_encoder
        self.kfolds = int(parsed_args.kfolds)
        operation = parsed_args.operation
        log_level = parsed_args.verbose

        # Set logging output options
        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])

        # Basic execution logic
        if operation == 'train':
            self.train()
            self.logger.info(f'Saved model to: {self.model_path}')
            self.logger.info(f'Saved label encoder to: {self.le_path}')
            return self.model_path
        elif operation == 'predict':
            role_prediction = self.predict()
            self.logger.info(f'{role_prediction}')
            return role_prediction


if __name__ == '__main__':
    host_footprint = HostFootprint()
    host_footprint.main()
