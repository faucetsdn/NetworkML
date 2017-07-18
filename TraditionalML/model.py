import numpy as np
from reader import sessionizer
from featurizer import extract_features

class LogRegModel:
    def __init__(
                    self,
                    duration,
                    means,
                    stds,
                    feature_list,
                    whitening,
                    model,
                    labels
                ):
        '''
        Initializes a logistic regression model.  This requires the mean
        and standard deviations from the training data, the IDs of the
        selected features, a whitening transform, and the fit logistic
        regression model.

        Args:
            duration: Size of time slices used in training
            means: Numpy 1D array of the feature means from training
            stds: Numpy 1D array of the standard deviations from training
            feature_list: List of the selected feature IDs
            whitening: Whitening transformation applied to the data
            model: Fit logistic regression model.
            labels: lookup table that maps a prediction to a label
        '''

        self.duration = duration
        self.means = means
        self.stds = stds
        self.feature_list = feature_list
        self.whitening = whitening
        self.model = model
        self.labels = labels

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
