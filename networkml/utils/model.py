import logging
import os
import pickle as pickle

import numpy as np
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

from networkml.parsers.pcap.featurizer import extract_features
from networkml.parsers.pcap.reader import sessionizer
from networkml.utils.training_utils import read_data
from networkml.utils.training_utils import select_features


logging.basicConfig(level=logging.INFO)


class Model:
    def __init__(self, duration, hidden_size=None, labels=None, model=None, model_type=None, threshold_time=None):
        '''
        Initializes functions shared in various models.

        Args:
            duration: Time duration to aggregate features for
        '''

        self.duration = duration
        self.hidden_size = hidden_size
        self.means = None
        self.stds = None
        self.feature_list = None
        self.model = model
        self.model_type = model_type
        self.labels = labels
        self.threshold_time = threshold_time
        self.sessions = None
        self.logger = logging.getLogger(__name__)
        try:
            if 'LOG_LEVEL' in os.environ and os.environ['LOG_LEVEL'] != '':
                self.logger.setLevel(os.environ['LOG_LEVEL'])
        except Exception as e:  # pragma: no cover
            self.logger.error(
                'Unable to set logging level because: {0} defaulting to INFO.'.format(str(e)))

    def _augment_data(self, X, y):
        '''
        Augments the data with randomly permuted samples. Added samples are
        labeled Unknown.

        Args:
            X: Numpy 2D array containing data to augment
            y: Numpy 1D array of labels to augment

        Returns:
            X_aug: Numpy 2D array containing augmented data
            y_aug: Numpy 1D array containing labels of augmented data
        '''

        # Randomly permute the inputs, and label the permutations Unknown
        X_permed = np.copy(X)
        for i in range(X_permed.shape[1]):
            np.random.shuffle(X_permed[:, i])

        y_permed = [self.labels.index('Unknown')]*X_permed.shape[0]
        y_permed = np.stack(y_permed)

        X_aug = np.concatenate((X, X_permed), axis=0)
        y_aug = np.concatenate((y, y_permed), axis=0)

        return X_aug, y_aug

    def get_features(self, filepath, source_ip=None):
        '''
        Reads a pcap specified by the file path and returns an array of the
        computed model inputs

        Args:
            filepath: Path to pcap to compute features for

        Returns:
            features: Numpy 2D array containing features for each time bin
            timestamp: datetime of the last observed packet
        '''

        # Read the capture into a feature array
        X = []
        timestamps = []
        binned_sessions = sessionizer(
            filepath, duration=self.duration, threshold_time=self.threshold_time)
        self.sessions = binned_sessions

        if len(binned_sessions) is 0:
            return None, None, None, None, None

        for session_dict in binned_sessions:
            if len(session_dict) > 0:
                if source_ip is None:
                    feature_list, source_ip, other_ips, capture_source_ip = extract_features(
                        session_dict
                    )
                else:
                    feature_list, _, other_ips, capture_source_ip = extract_features(
                        session_dict,
                        capture_source=source_ip
                    )
                X.append(feature_list)
                last_packet = list(session_dict.items())[-1]
                timestamps.append(last_packet[1][0][0])

        if len(X) == 0:
            return None, None, None, None, None

        full_features = np.stack(X)

        # Mean normalize the features
        full_features -= np.expand_dims(self.means, 0)
        full_features /= np.expand_dims(self.stds, 0)
        features = full_features[:, self.feature_list]
        return features, source_ip, timestamps, other_ips, capture_source_ip

    def train(self, data_dir):
        '''
        Trains a single layer model on the data contained in the specified
        directory.  Labels found in the directory are augmented with an
        unknown label.

        Args:
            data_dir: Directory containing the training data
        '''

        self.logger.info('Reading data')
        # First read the data directory for the features and labels
        X_all, y_all, new_labels = read_data(
            data_dir,
            duration=self.duration,
            labels=self.labels
        )
        self.labels = new_labels

        self.logger.info('Making data splits')
        # Split the data into training, validation, and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X_all,
            y_all,
            test_size=0.2,
            random_state=0
        )

        self.logger.info('Normalizing features')
        # Mean normalize the features, saving the means and variances
        self.means = X_train.mean(axis=0)
        self.stds = X_train.std(axis=0)
        # Set the zero standard deviations to 1
        zero_stds = self.stds <= 1
        self.stds[zero_stds] = 1
        # Apply the mean normalization transformation to the training dataj
        X_normed = X_train - np.expand_dims(self.means, 0)
        X_normed /= np.expand_dims(self.stds, 0)

        self.logger.info('Doing feature selection')
        # Select the relevant features from the training set
        self.feature_list = select_features(X_normed, y_train)
        self.logger.info(self.feature_list)

        # If hidden size wasn't specified, default to the mean of the number
        # of features and the size of the label space
        if self.hidden_size is None:
            self.hidden_size = int(1/2*(
                len(self.labels) +
                len(self.feature_list)
            )
            )

        # Augment the data with randomly permuted samples
        X_aug, y_aug = self._augment_data(X_normed, y_train)

        # Fit the one layer model to the augmented training data
        X_input = X_aug[:, self.feature_list]

        self.model.fit(X_input, y_aug)

        # Evaulate the model on the augmented test data
        X_test_input = X_test - np.expand_dims(self.means, 0)
        X_test_input /= np.expand_dims(self.stds, 0)
        X_test_aug, y_test_aug = self._augment_data(X_test_input, y_test)
        predictions = self.model.predict(X_test_aug[:, self.feature_list])
        self.logger.info('F1 score:')
        self.logger.info(f1_score(y_test_aug, predictions, average='weighted'))

    def predict(self, filepath, source_ip=None):
        '''
        Read a capture file from the specified path and make a prediction
        of the source.

        Args:
            filepath: Path of capture file to read

        Returns:
            prediction: list of tuples formatted as (source, probability)
        '''

        features, _, _, _, _ = self.get_features(filepath, source_ip=source_ip)

        if features is None:
            return None
        predictions = self.model.predict_proba(features)
        mean_predictions = np.mean(predictions, axis=0)

        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(mean_predictions)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)
        return prediction

    def get_representation(self, filepath, mean=True, source_ip=None):
        '''
        Computes the mean hidden representation of the input file.

        Args:
            filepath: Path of capture file to represent
            mean: If true(default), averages all the representations into one

        Returns:
            representation:  representation vector of the input file
        '''

        features, source_ip, timestamp, other_ips, capture_ip_source = self.get_features(
            filepath,
            source_ip=source_ip,
        )
        if features is None:
            return None, None, None, None, None, None

        probabilities = []
        representation = features
        if self.model_type == 'randomforest':
            mean_rep = np.mean(representation, axis=0)
            probabilities = self.model.predict_proba(mean_rep.reshape(1, -1))
            probabilities = probabilities[0]
        elif self.model_type == 'onelayer':
            L1_weights = self.model.coefs_[0]
            L1_biases = self.model.intercepts_[0]
            representation = np.maximum(
                np.matmul(features, L1_weights)+L1_biases,
                0
            )

            mean_rep = np.mean(representation, axis=0)

            L2_weights = self.model.coefs_[1]
            L2_biases = self.model.intercepts_[1]
            probabilities = np.matmul(representation, L2_weights) + L2_biases
            probabilities = np.exp(probabilities)
            probabilities /= np.expand_dims(
                np.sum(probabilities, axis=1), axis=1)
            probabilities = np.mean(probabilities, axis=0)

        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(probabilities)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)

        if mean:
            representation = mean_rep
            timestamp = timestamp[-1]

        return representation, source_ip, timestamp, prediction, other_ips, capture_ip_source

    def calc_f1(self, results, ignore_unknown=False):
        results_by_label = {}
        for file, file_results in results.items():
            if file != 'labels':
                indiv_results = file_results['individual']
                true_label = file_results['label']

                if true_label not in results_by_label:
                    if true_label == 'Unknown':
                        if ignore_unknown is False:
                            results_by_label[true_label] = {
                                'tp': 0, 'fp': 0, 'fn': 0}
                    else:
                        results_by_label[true_label] = {
                            'tp': 0, 'fp': 0, 'fn': 0}

                for _, classification in indiv_results.items():
                    class_label = classification[0][0]
                    if class_label == 'Unknown' and ignore_unknown is True:
                        class_label = classification[1][0]
                    if class_label not in results_by_label:
                        results_by_label[class_label] = {
                            'tp': 0, 'fp': 0, 'fn': 0}
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
            except Exception as e:
                self.logger.debug(
                    'Setting precision and recall to 0 because: {0}'.format(str(e)))
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
                    self.logger.info('F1 of {} for {}'.format(f1, label))

        self.logger.info('Mean F1: {}'.format(np.mean(f1s)))

    def classify_representation(self, representation):
        '''
        Takes in a representation and produces a classification
        '''
        probabilities = []
        if self.model_type == 'randomforest':
            probabilities = self.model.predict_proba(
                representation.reshape(1, -1))
            probabilities = probabilities[0]
        elif self.model_type == 'onelayer':
            L2_weights = self.model.coefs_[1]
            L2_biases = self.model.intercepts_[1]
            probabilities = np.matmul(representation, L2_weights) + L2_biases
            probabilities = np.exp(probabilities)
            probabilities /= np.sum(probabilities)
        prediction = [
            (self.labels[i], prob)
            for i, prob in enumerate(probabilities)
        ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)

        return prediction

    def save(self, save_path):
        '''
        Saves the model to the specified file path

        Args:
            save_path: Path to store the saved model at.
        '''

        model_attributes = {
            'duration': self.duration,
            'hidden_size': self.hidden_size,
            'means': self.means,
            'stds': self.stds,
            'feature_list': self.feature_list,
            'model': self.model,
            'labels': self.labels
        }

        with open(save_path, 'wb') as handle:
            pickle.dump(model_attributes, handle)

    def load(self, load_path):
        '''
        Load the model parameters from the specified path.

        Args:
            load_path: Path to load the model parameters from
        '''

        with open(load_path, 'rb') as handle:
            model_attributes = pickle.load(handle)

        self.duration = model_attributes['duration']
        self.hidden_size = model_attributes['hidden_size']
        self.means = model_attributes['means']
        self.stds = model_attributes['stds']
        self.feature_list = model_attributes['feature_list']
        self.model = model_attributes['model']
        self.labels = model_attributes['labels']
