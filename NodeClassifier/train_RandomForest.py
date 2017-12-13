'''
Trains and saves an instance of the one layer feedforward model on the
data directory specified by the first argument.  The model is saved to the
location specified by the second argument.
'''

import sys
import json
from utils.RandomForestModel import RandomForestModel

if __name__ == '__main__':
    # Load model params from config
    with open('config.json') as config_file:
        config = json.load(config_file)
        duration = config['duration']
        labels = config['labels']

    # Get the data directory
    data_dir = sys.argv[1]
    # Initialize the model
    model = RandomForestModel(
                        duration=duration,
                        labels=labels
                       )
    # Train the model
    model.train(data_dir)
    # Save the model to the specified path
    save_path = sys.argv[2]
    model.save(save_path)
