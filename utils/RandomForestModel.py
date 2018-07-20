import numpy as np
import pickle as pickle
try:
    from .reader import sessionizer
    from .featurizer import extract_features
    from .training_utils import read_data
    from .training_utils import select_features
except SystemError:
    from reader import sessionizer
    from featurizer import extract_features
    from training_utils import read_data
    from training_utils import select_features

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score


class RandomForestModel:
    def __init__(self, duration, hidden_size=None, labels=None):
        '''
        Initializes a model with a single hidden layer.  Features are
        aggregated over the time specified by the duration and the hidden
        layer size is a hyperparameter set at initialization.

        Args:
            duration: Time duration to aggregate features for
        '''

        self.duration = duration
        self.hidden_size = hidden_size

        self.means = None
        self.stds = None
        self.feature_list = None
        self.model = None
        self.labels = labels

        self.sessions = None

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
            np.random.shuffle(X_permed[:,i])

        y_permed = [self.labels.index("Unknown")]*X_permed.shape[0]
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
        binned_sessions = sessionizer(filepath, duration=self.duration)
        self.sessions = binned_sessions

        if len(binned_sessions) is 0:
            return None, None, None, None

        for session_dict in binned_sessions:
            if len(session_dict) > 0:
                if source_ip is None:
                    feature_list, source_ip, other_ips = extract_features(
                                                                    session_dict
                                                                         )
                else:
                    feature_list, _, other_ips = extract_features(
                                                        session_dict,
                                                        capture_source=source_ip
                                                                 )
                X.append(feature_list)
                last_packet = list(session_dict.items())[-1]
                timestamps.append(last_packet[1][0][0])

        if len(X) == 0:
            return None, None, None, None

        full_features = np.stack(X)

        # Mean normalize the features
        full_features -= np.expand_dims(self.means, 0)
        full_features /= np.expand_dims(self.stds, 0)
        features = full_features[:, self.feature_list]

        return features, source_ip, timestamps, other_ips


    def train(self, data_dir):
        '''
        Trains a single layer model on the data contained in the specified
        directory.  Labels found in the directory are augmented with an
        unknown label.

        Args:
            data_dir: Directory containing the training data
        '''

        print("Reading data")
        # First read the data directory for the features and labels
        X_all, y_all, new_labels = read_data(
                                              data_dir,
                                              duration=self.duration,
                                              labels=self.labels
                                            )
        self.labels = new_labels

        print("Making data splits")
        # Split the data into training, validation, and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
                                                            X_all,
                                                            y_all,
                                                            test_size=0.2,
                                                            random_state=0
                                                           )

        print("Normalizing features")
        # Mean normalize the features, saving the means and variances
        self.means = X_train.mean(axis=0)
        self.stds = X_train.std(axis=0)
        # Set the zero standard deviations to 1
        zero_stds = self.stds <= 1
        self.stds[zero_stds] = 1
        # Apply the mean normalization transformation to the training dataj
        X_normed = X_train - np.expand_dims(self.means, 0)
        X_normed /= np.expand_dims(self.stds, 0)

        print("Doing feature selection")
        # Select the relevant features from the training set
        self.feature_list = select_features(X_normed, y_train)
        print(self.feature_list)

        # If hidden size wasn't specified, default to the mean of the number
        # of features and the size of the label space
        if self.hidden_size is None:
            self.hidden_size = int(1/2*(
                                        len(self.labels) + \
                                        len(self.feature_list)
                                       )
                                  )

        # Augment the data with randomly permuted samples
        X_aug, y_aug = self._augment_data(X_normed, y_train)

        # Fit the one layer model to the augmented training data
        X_input = X_aug[:, self.feature_list]
        self.model = RandomForestClassifier(
                                            n_estimators=100,
                                            min_samples_split=5,
                                            class_weight='balanced'
                                           )
        self.model.fit(X_input, y_aug)

        # Evaulate the model on the augmented test data
        X_test_input = X_test - np.expand_dims(self.means, 0)
        X_test_input /= np.expand_dims(self.stds, 0)
        X_test_aug, y_test_aug = self._augment_data(X_test_input, y_test)
        predictions = self.model.predict(X_test_aug[:, self.feature_list])
        print("F1 score:",
                f1_score(y_test_aug, predictions, average='weighted'))

    def predict(self, filepath, source_ip=None):
        '''
        Read a capture file from the specified path and make a prediction
        of the source.

        Args:
            filepath: Path of capture file to read

        Returns:
            prediction: list of tuples formatted as (source, probability)
        '''

        features, _, _, _ = self.get_features(filepath, source_ip=source_ip)

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

        features, source_ip, timestamp, other_ips = self.get_features(
                                                           filepath,
                                                           source_ip=source_ip,
                                                                     )
        if features is None:
            return None, None, None, None, None

        representation = features
        mean_rep = np.mean(representation, axis=0)

        probabilities = self.model.predict_proba(mean_rep.reshape(1,-1))
        probabilities = probabilities[0]
        prediction = [
                        (self.labels[i], prob)
                        for i, prob in enumerate(probabilities)
                     ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)

        if mean:
            representation = mean_rep
            timestamp = timestamp[-1]

        return representation, source_ip, timestamp, prediction, other_ips

    def classify_representation(self, representation):
        '''
        Takes in a representation and produces a classification
        '''
        probabilities = self.model.predict_proba(representation.reshape(1,-1))
        probabilities = probabilities[0]
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
        self.means = model_attributes['means']
        self.stds = model_attributes['stds']
        self.feature_list = model_attributes['feature_list']
        self.model = model_attributes['model']
        self.labels = model_attributes['labels']
