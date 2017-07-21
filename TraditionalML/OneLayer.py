import numpy as np
from reader import sessionizer
from featurizer import extract_features

from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import f1_score

from training_utils import read_data
from training_utils import select_features

class OneLayerModel:
    def __init__(self, duration, hidden_size):
        '''
        Initializes a model with a single hidden layer.  Features are
        aggregated over the time specified by the duration and the hidden
        layer size is a hyperparameter set at initialization.

        Args:
            duration: Time duration to aggregate features for
            hidden_size: size of hidden layer
        '''

        self.duration = duration
        self.hidden_size = hidden_size

        self.means = None
        self.stds = None
        self.feature_list = None
        self.model = None
        self.labels = None

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
        X_permed = [
                    np.random.permutation(X[i])
                    for i in range(X.shape[0])
                   ]
        np.random.shuffle(X_permed)
        y_permed = [self.labels.index("Unknown")]*len(X_permed)
        X_permed, y_permed = np.stack(X_permed), np.stack(y_permed)
        X_aug = np.concatenate((X, X_permed), axis=0)
        y_aug = np.concatenate((y, y_permed), axis=0)

        return X_aug, y_aug

    def get_features(self, filepath):
        '''
        Reads a pcap specified by the file path and returns an array of the
        computed model inputs

        Args:
            filepath: Path to pcap to compute features for

        Returns:
            features: Numpy 2D array containing features for each time bin
        '''

        # Read the capture into a feature array
        X = []
        binned_sessions = sessionizer(filepath, duration=self.duration)
        for session_dict in binned_sessions:
            feature_list = extract_features(session_dict)
            X.append(feature_list)
        full_features = np.stack(X)

        # Mean normalize the features
        full_features -= np.expand_dims(self.means, 0)
        full_features /= np.expand_dims(self.stds, 0)
        features = full_features[:, self.feature_list]

        return features


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
        X_all, y_all, self.labels = read_data(data_dir, duration=self.duration)
        self.labels.append("Unknown")

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
        zero_stds = self.stds == 0
        self.stds[zero_stds] = 1
        # Apply the mean normalization transformation to the training dataj
        X_normed = X_train - np.expand_dims(self.means, 0)
        X_normed /= np.expand_dims(self.stds, 0)

        print("Doing feature selection")
        # Select the relevant features from the training set
        self.feature_list = select_features(X_normed, y_train)
        print(self.feature_list)

        # Augment the data with randomly permuted samples
        X_aug, y_aug = self._augment_data(X_normed, y_train)

        # Fit the one layer model to the augmented training data
        X_input = X_aug[:, self.feature_list]
        self.model = MLPClassifier(
                                    (self.hidden_size),
                                    activation='tanh',
                                    max_iter=1000
                                  )

        self.model.fit(X_input, y_aug)

        # Evaulate the model on the augmented test data
        X_test_input = X_test - np.expand_dims(self.means, 0)
        X_test_input /= np.expand_dims(self.stds, 0)
        X_test_aug, y_test_aug = self._augment_data(X_test_input, y_test)
        predictions = self.model.predict(X_test_aug[:, self.feature_list])
        print("F1 score:",
                f1_score(y_test_aug, predictions, average='weighted'))

    def predict(self, filepath):
        '''
        Read a capture file from the specified path and make a prediction
        of the source.

        Args:
            filepath: Path of capture file to read

        Returns:
            prediction: list of tuples formatted as (source, probability)
        '''

        features = self.get_features(filepath)

        predictions = self.model.predict_proba(features)
        mean_predictions = np.mean(predictions, axis=0)

        prediction = [
                      (self.labels[i], prob)
                      for i, prob in enumerate(mean_predictions)
                     ]
        prediction = sorted(prediction, key=lambda x: x[1], reverse=True)
        return prediction

    def get_representation(self, filepath):
        '''
        Computes the mean hidden representation of the input file.

        Args:
            filepath: Path of capture file to represent

        Returns:
            representation:  representation vector of the input file
        '''

        features = self.get_features(filepath)
        L1_weights = self.model.coefs_[0]
        L1_biases = self.model.intercepts_[0]
        representation = np.tanh(np.matmul(features, L1_weights) + L1_biases)
        representation = np.mean(representation, axis=0)

        return representation
