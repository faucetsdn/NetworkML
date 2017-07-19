import numpy as np
from reader import sessionizer
from featurizer import extract_features

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

from training_utils import read_data
from training_utils import select_features
from training_utils import whiten_features
from training_utils import choose_regularization

class LogRegModel:
    def __init__(self, duration):
        '''
        Initializes a logistic regression model with a specified time
        window

        Args:
            duration: Size of time slices used in training
        '''

        self.duration = duration
        self.means = None
        self.stds = None
        self.feature_list = None
        self.whitening = None
        self.model = None
        self.labels = None

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

        # Apply the whitening transformation to the features
        features = self.whitening.transform(features)

        return features

    def train(self, data_dir):
        '''
        Trains the model on the contents of the data directory

        Args:
            datadir: Directory containing the training data
        '''
        print("Reading data")
        # First read the data directory for the features and labels
        X_all, y_all, labels = read_data(data_dir, duration=self.duration)

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
        print("Decorrelating features")
        # Decorrelate the selected features
        self.whitening = whiten_features(
                                          X_normed[:, self.feature_list]
                                        )
        X_input = self.whitening.transform(X_normed[:, self.feature_list])

        print("Selecting C")
        # Use a grid search with cross validation to select the hyperparameter
        C = choose_regularization(X_input, y_train)

        print("Fitting model")
        # Fit the final logistic regression model using this value of C
        self.model = LogisticRegression(
                                    C=C,
                                    multi_class='multinomial',
                                    solver='newton-cg',
                                    class_weight='balanced'
                                  )
        self.model.fit(X_input, y_train)

        X_test_input = X_test - np.expand_dims(self.means, 0)
        X_test_input /= np.expand_dims(self.stds, 0)
        X_test_input = self.whitening.transform(
                                            X_test_input[:, self.feature_list]
                                          )
        predictions = self.model.predict(X_test_input)
        print("F1 score:", f1_score(y_test,predictions,average='weighted'))


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

        return prediction
