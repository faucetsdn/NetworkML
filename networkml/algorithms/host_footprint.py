"""
A class to perform machine learning operations on computer network traffic
"""
import argparse
import ast
import json
import logging
import os
from collections import defaultdict

import joblib
import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.model_selection import GridSearchCV
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelBinarizer

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
        self.list = None
        self.model_path = None

    @staticmethod
    def regularize_df(df):
        # need host_key, tshark_srcips, and frame_epoch to send
        # source_ip/source_mac to Poseidon.
        cols = [col for col in ('host_key', 'tshark_srcips', 'tshark_frame_epoch', 'role') if col in df.columns]
        # TODO: remove ratio features for now for model compatibility.
        cols.extend([col for col in df.columns if 'ratio' in col])
        host_key = df.get('host_key', None)
        tshark_srcips = df.get('tshark_srcips', None)
        frame_epoch = df.get('tshark_frame_epoch', None)
        df = df.drop(columns=cols)
        # Dataframe column order must be the same for train/predict!
        df = df.reindex(columns=sorted(df.columns))
        return df, host_key, tshark_srcips, frame_epoch

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
    def serialize_model(model, path):
        """Serialize lmodel to enable persistence
        without pickling the file. .pkl files are a security
        risk and should be avoided
        Model is saved as a JSON object.
        INPUT:
        --model: the model object (an MLPClassifier from sklearn) to be saved
        --path: filepath for saving the object
        OUTPUT:
        --Does not return anything
        """
        def serialize_label_binarizer(label_binarizer):
            serialized_label_binarizer = {
                'neg_label': label_binarizer.neg_label,
                'pos_label': label_binarizer.pos_label,
                'sparse_output': label_binarizer.sparse_output,
                'y_type_': label_binarizer.y_type_,
                'sparse_input_': label_binarizer.sparse_input_,
                'classes_': label_binarizer.classes_.tolist()
            }

            return serialized_label_binarizer

        serialized_model = {
            'meta': 'mlp',
            'coefs_': [array.tolist() for array in model.coefs_],
            'loss_': model.loss_,
            'intercepts_': [array.tolist() for array in model.intercepts_],
            'n_iter_': model.n_iter_,
            'n_layers_': model.n_layers_,
            'n_outputs_': model.n_outputs_,
            'out_activation_': model.out_activation_,
            '_label_binarizer': serialize_label_binarizer(model._label_binarizer),
            'params': model.get_params(),
            'features':model.features,
        }

        if isinstance(model.classes_, list):
            serialized_model['classes_'] = [array.tolist() for array in model.classes_]
        else:
            serialized_model['classes_'] = model.classes_.tolist()

        with open(path, 'w') as out_file:
            json.dump(serialized_model, out_file, indent=2)
        #skljson.to_json(model, path)

    @staticmethod
    def deserialize_model(path):
        """Deserialize JSON object storing the ml model.
        Model (an MLPClassifier from sklearn) is re-instantiated
        with proper values.
        INPUT:
        --path: filepath for loading the JSON object
        OUTPUT:
        --model: Returns an MLPClassifier (sklearn) object
        """
        def deserialize_label_binarizer(label_binarizer_dict):
            label_binarizer = LabelBinarizer()
            label_binarizer.neg_label = label_binarizer_dict['neg_label']
            label_binarizer.pos_label = label_binarizer_dict['pos_label']
            label_binarizer.sparse_output = label_binarizer_dict['sparse_output']
            label_binarizer.y_type_ = label_binarizer_dict['y_type_']
            label_binarizer.sparse_input_ = label_binarizer_dict['sparse_input_']
            label_binarizer.classes_ = np.array(label_binarizer_dict['classes_'])

            return label_binarizer

        # Load (or deserialize) model from JSON
        model_dict = {}
        with open(path, 'r') as in_file:
            model_dict = json.load(in_file)

        model = MLPClassifier(**model_dict['params'])

        model.coefs_ = np.array(model_dict['coefs_'], dtype=object)
        model.loss_ = model_dict['loss_']
        model.intercepts_ = np.array(model_dict['intercepts_'], dtype=object)
        model.n_iter_ = model_dict['n_iter_']
        model.n_layers_ = model_dict['n_layers_']
        model.n_outputs_ = model_dict['n_outputs_']
        model.out_activation_ = model_dict['out_activation_']
        model._label_binarizer = deserialize_label_binarizer(model_dict['_label_binarizer'])
        model.features = list(model_dict['features'])

        model.classes_ = np.array(model_dict['classes_'])
        # Convert coeficients to numpy arrays to enable JSON deserialization
        # This is a hack to compensate for a bug in sklearn_json
        for i, x in enumerate(model.coefs_):
            model.coefs_[i] = np.array(x)
        return model

    @staticmethod
    def serialize_scaler(scaler, path):
        return joblib.dump(scaler, path)

    @staticmethod
    def deserialize_scaler(path):
        return joblib.load(path)

    @staticmethod
    def parse_args(raw_args=None):
        """
        Use python's argparse module to collect command line arguments
        for using this class
        """
        netml_path = list(networkml.__path__)
        parser = argparse.ArgumentParser()
        parser.add_argument('path', help='path to a single csv file')
        parser.add_argument('--eval_data',
                            help='path to eval CSV file, if training')
        parser.add_argument('--kfolds', '-k',
                            default=5,
                            help='specify number of folds for k-fold cross validation')
        parser.add_argument('--label_encoder', '-l',
                            default=os.path.join(netml_path[0],
                                                 'trained_models/host_footprint_le.json'),
                            help='specify a path to load or save label encoder')
        parser.add_argument('--scaler',
                            default=os.path.join(netml_path[0],
                                                 'trained_models/host_footprint_scaler.mod'),
                            help='specify a path to load or save scaler')
        parser.add_argument('--operation', '-O', choices=['train', 'predict', 'eval'],
                            default='predict',
                            help='choose which operation task to perform, \
                            train or predict (default=predict)')
        parser.add_argument('--trained_model',
                            default=os.path.join(netml_path[0],
                                                 'trained_models/host_footprint.json'),
                            help='specify a path to load or save trained model')
        parser.add_argument('--list', '-L',
                            choices=['features'],
                            default=None,
                            help='list information contained within model defined by --trained_model')
        parser.add_argument('--verbose', '-v',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                            default='INFO',
                            help='logging level (default=INFO)')
        parser.add_argument('--train_unknown', default=False, action='store_true',
                            help='Train on unknown roles')
        parsed_args = parser.parse_args(raw_args)
        return parsed_args

    def _get_test_train_csv(self, path, train_unknown):
        df, _, _, _ = self.regularize_df(pd.read_csv(path))
        df = df.fillna(0)
        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        df['role'] = df.filename.str.split('-').str[0]
        # Drop unknown roles.
        if not train_unknown:
            df = df[df['role'] != 'Unknown']
        X = df.drop(['filename', 'role'], axis=1)
        y = df.role
        column_list = list(X.columns.values)
        X = self.string_feature_check(X)
        return (X, y, column_list)

    def summarize_eval_data(self, model, scaler, label_encoder, eval_data, train_unknown):
        X_test, y_true, _ = self._get_test_train_csv(eval_data, train_unknown)
        X_test = scaler.transform(X_test)
        y_true = label_encoder.transform(y_true)
        y_pred = model.predict(X_test)

        for metric, name in (
                (accuracy_score, 'accuracy'),
                (precision_score, 'precision'),
                (recall_score, 'recall'),
                (f1_score, 'f1')):
            if metric == accuracy_score:
                val = metric(y_true, y_pred)
            else:
                val = metric(y_true, y_pred, average='weighted')
            val = np.round(val, 4)
            self.logger.info(f'{name}: {val}')

        conf_matrix = confusion_matrix(y_true, y_pred)
        self.logger.info(conf_matrix)
        self.logger.info(label_encoder.classes_.tolist())

    def eval(self, path, scaler_path, le_path, model_path, train_unknown):
        """
        Accept CSV and summarize based on already trained model.
        """
        scaler = self.deserialize_scaler(scaler_path)
        le = self.deserialize_label_encoder(le_path)
        self.model = self.deserialize_model(model_path)
        self.summarize_eval_data(self.model, scaler, le, path, train_unknown)

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
        X, y, cols = self._get_test_train_csv(self.path, self.train_unknown)

        unique_roles = sorted(y.unique())
        self.logger.info(f'inferring roles {unique_roles}')

        # Normalize X features before training
        scaler = preprocessing.StandardScaler()
        scaler.fit(X)
        X = scaler.transform(X)

        # Convert y into categorical/numerical feature
        le = preprocessing.LabelEncoder()
        y = le.fit_transform(y)

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
        self.model.features = cols

        # Save model to JSON
        self.serialize_model(self.model, self.model_path)
        self.serialize_scaler(scaler, self.scaler)
        self.serialize_label_encoder(le, self.le_path)

        if self.eval_data:
            self.summarize_eval_data(self.model, self.scaler, self.le_path, self.eval_data, self.train_unknown)

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
        scaler = self.deserialize_scaler(self.scaler)
        # Get label encoder
        le = self.deserialize_label_encoder(self.le_path)
        # Load (or deserialize) model from JSON
        self.model = self.deserialize_model(self.model_path)

        # Load data from host footprint .csv
        csv_df = pd.read_csv(self.path)
        df, host_key, tshark_srcips, frame_epoch = self.regularize_df(csv_df)
        # Split dataframe into X (the input features or predictors)
        # and y (the target or outcome or dependent variable)
        # This drop function should work even if there is no column
        # named filename
        X = df.drop('filename', axis=1)

        # Get filenames to match to predictions
        filename = df.filename

        # Normalize X features before predicting
        X = scaler.transform(X)

        self.logger.info(f'Executing model inference')
        # Make model predicton - Will return a vector of values
        predictions_rows = self.model.predict_proba(X)

        # Dict to store top role and list of top roles
        all_predictions = self.get_individual_predictions(
            predictions_rows, le, filename, host_key, tshark_srcips, frame_epoch)

        return json.dumps(all_predictions)

    def get_individual_predictions(self, predictions_rows, label_encoder,
                                   filename, host_key, tshark_srcips,
                                   frame_epoch, top_n_roles=3):
        """ Return role predictions for given device

        INPUTS:
        --predictions_rows: each device is represented as a row
        --label_encoder: a mapping of device role name to numerical category
        --filename: the filename of the pcap for which a prediction is made
        --host_key: canonical source MAC for this pcap.
        --tshark_srcips: canonical source IPs for this pcap.
        --frame_epoch: the timestamp of the packet.

        OUTPUTS:
        --all_predictions: a dict with the filename for a key and a
        JSON'ified dict for a value. see sorted_roles_to_json() for a description
        of the value's structure.
        """

        # Dict to store JSON of top n roles and probabilities per device
        all_predictions = defaultdict(list)
        num_roles = len(label_encoder.classes_)
        labels = label_encoder.inverse_transform([i for i in range(num_roles)])

        # Loop thru different devices on which to make prediction
        for i, predictions in enumerate(predictions_rows):
            role_list = [(k, v) for k, v in zip(labels, predictions)]
            # Sort role list by probabilities
            role_list_sorted = sorted(role_list, key=lambda x: x[1], reverse=True)[:top_n_roles]
            # Dump top role and roles-probability list
            host_results = self.sorted_roles_to_dict(role_list_sorted)
            if host_key is not None:
                host_results.update({'source_mac': host_key[i]})
            if tshark_srcips is not None:
                source_ip = ast.literal_eval(tshark_srcips[i])
                if source_ip:
                    source_ip = source_ip[0]
                else:
                    source_ip = None
                host_results.update({'source_ip': source_ip})
            if frame_epoch is not None:
                host_results.update({'timestamp': frame_epoch[i]})
            all_predictions[filename[i]].append(host_results)

        return all_predictions


    @staticmethod
    def sorted_roles_to_dict(role_list_sorted, threshold=.5):
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
        --predictions: a dict with the top role and a sorted role list
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
        role_predictions = {
            'top_role': top_role,
            'role_list': role_list_sorted,
        }

        return role_predictions


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


    def list_model(self):
        model = self.deserialize_model(self.model_path)
        if self.list == 'features':
            return model.features


    def main(self):
        """
        Collect and parse command line arguments for using this class
        """

        # Collect command line arguments
        parsed_args = HostFootprint.parse_args(raw_args=self.raw_args)
        self.path = parsed_args.path
        self.eval_data = parsed_args.eval_data
        self.model_path = parsed_args.trained_model
        self.le_path = parsed_args.label_encoder
        self.scaler = parsed_args.scaler
        self.kfolds = int(parsed_args.kfolds)
        self.train_unknown = parsed_args.train_unknown
        self.list = parsed_args.list
        operation = parsed_args.operation
        log_level = parsed_args.verbose

        # Set logging output options
        log_levels = {'INFO': logging.INFO, 'DEBUG': logging.DEBUG,
                      'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
        logging.basicConfig(level=log_levels[log_level])

        self.logger.debug(f'hostfootprint.main list: {self.list}')
        if self.list:
            model_list = self.list_model()
            if model_list and len(model_list) > 0:
                result = f'Listing {self.list} for model at {self.model_path}:\n{model_list}'
                return result
            else:
                return f'model found at {self.model_path} contains no {self.list}'

        # Basic execution logic
        if operation == 'train':
            if not self.train_unknown:
                self.logger.info(f'Role Unknown will be dropped from training data')
            self.train()
            self.logger.info(f'Saved model to: {self.model_path}')
            self.logger.info(f'Saved label encoder to: {self.le_path}')
            return self.model_path
        if operation == 'predict':
            role_prediction = self.predict()
            self.logger.info(f'{role_prediction}')
            return role_prediction
        if operation == 'eval':
            return self.eval(self.path, self.scaler, self.le_path, self.model_path, self.train_unknown)
        return None


if __name__ == '__main__':
    host_footprint = HostFootprint()
    host_footprint.main()
