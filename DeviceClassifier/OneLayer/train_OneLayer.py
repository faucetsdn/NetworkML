'''
Trains and saves an instance of the one layer feedforward model on the
data directory specified by the first argument.  The model is saved to the
location specified by the second argument.
'''
import json
import sys

from poseidonml.Model import Model
from sklearn.neural_network import MLPClassifier


if __name__ == '__main__':
    # Load model params from config
    with open('opts/config.json') as config_file:
        config = json.load(config_file)
        duration = config['duration']
        hidden_size = config['state size']
        labels = config['labels']

    # Get the data directory
    if len(sys.argv) < 2:
        data_dir = '/pcaps'
    else:
        data_dir = sys.argv[1]

    m = MLPClassifier(
        (hidden_size),
        alpha=0.1,
        activation='relu',
        max_iter=1000
    )

    # Initialize the model
    model = Model(
        duration=duration,
        hidden_size=hidden_size,
        labels=labels,
        model=m,
        model_type='OneLayer'
    )
    # Train the model
    model.train(data_dir)
    # Save the model to the specified path
    if len(sys.argv) == 3:
        save_path = sys.argv[2]
    else:
        save_path = 'models/OneLayerModel.pkl'
    model.save(save_path)
