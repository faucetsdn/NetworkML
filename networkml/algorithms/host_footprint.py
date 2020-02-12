import json
import logging
import sys

import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.neural_network import MLPClassifier


class HostFootprint():


    def __init__(self, path, operation, model=None, le=None, scaler_fitted=None):
        self.logger = logging.getLogger(__name__)
        self.path = path
        self.operation = operation
        self.model = model
        self.le = le
        self.scaler_fitted = scaler_fitted
        if self.operation == 'train':
            self.train()
            print(f'{self.model} {self.le} {self.scaler_fitted}')
        elif self.operation == 'predict':
            self.train()
            role_prediction = self.predict()
            print(f'{role_prediction}')
        else:
            self.logger.error('Unknown operation choice')
        return


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

        ## Load data from host footprint .csv
        df = pd.read_csv(self.path)

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
        X = self.stringFeatureCheck(X)

        ## Normalize X features before training
        scaler = preprocessing.MinMaxScaler()
        self.scaler_fitted = scaler.fit(X)
        X = self.scaler_fitted.transform(X)

        ## Convert y into categorical/numerical feature
        self.le = preprocessing.LabelEncoder()
        y = self.le.fit_transform(y)

        ## Calculate number of categories to predict
        num_categories = len(self.le.classes_)

        ## Train model
        clf = MLPClassifier(solver='sgd',
                            hidden_layer_sizes=(64, 32, num_categories),
                            random_state=1999)

        self.model = clf.fit(X, y)

        return

    def stringFeatureCheck(self, X):
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
                self.logger.info(f'String object found in column {col}')

                ## Expand features into "dummy", i.e. 0/1
                ## features
                new_features = pd.get_dummies(X[col])

                ## Add new features onto X dataframe
                X = pd.concat([X, new_features], axis=1)

                ## Remove original non-expanded feature from X
                X = X.drop(col, axis=1)

        return X


    def predict(self):
        """
        This function takes a csv of features at the host footprint level and then makes
        a role prediction for each row. The output is the top three roles.

        OUTPUTS:
        --prediction: top three roles for each host and the associated probability of each role
        (in json format)
        """

        ## Load data from host footprint .csv
        df = pd.read_csv(self.path)

        ## Check if there is greater than 1 row, there should
        ## only be one row
        if df.shape[0] > 1:
            ## log warning
            self.logger.error(f'More than one row found in predict_input csv')

        ## Split dataframe into X (the input features or predictors)
        ## and y (the target or outcome or dependent variable)
        ## This drop function should work even if there is no column
        ## named filename
        X = df.drop("filename", axis=1)

        # get filenames to match to predictions if they exist
        y = df.filename

        ## Normalize X features before training
        scaler = preprocessing.MinMaxScaler()
        X = self.scaler_fitted.transform(X) ## Use already fitted scaler

        ## Make model predicton - Will return a vector of values
        predictions_rows = self.model.predict_proba(X) ## Convert list with one list
                                                       ## item into just one list

        ## Output JSON of top three roles and probabilities

        ## These operations do NOT create a sorted list
        ## NOTE: To change the number of roles for which you want a prediction
        ## change the number number in the argpartition line of code
        all_predictions = {}
        for counter,predictions in enumerate(predictions_rows):
            ind = np.argpartition(predictions, 3)[-3:] ## Index of top three roles
            labels = self.le.inverse_transform(ind) ## top three role names
            probs = predictions[ind] ## probability of top three roles

            ## Put labels and probabilities into list
            role_list = [(k, v) for k,v in zip(labels, probs)]

            ## Sort role list by probabilities
            role_list_sorted = sorted(role_list, key=lambda x: x[1], reverse=True)

            ## Place roles and probabilities in json
            role_predictions = json.dumps(role_list_sorted)
            all_predictions[y[counter]] = role_predictions

        return all_predictions


if __name__ == "__main__":
    if len(sys.argv) == 3:
        path = sys.argv[1]
        operation = sys.argv[2]
    else:
        logging.error('No path provided, and/or no operation chosen')
        sys.exit(1)

    host_footprint = HostFootprint(path, operation)
