'''
Trains and saves an instance of the one layer feedforward model on the
data directory specified by the first argument.  The model is saved to the
location specified by the second argument.
'''

import sys
from OneLayer import OneLayerModel

if __name__ == '__main__':
    # Get the data directory
    data_dir = sys.argv[1]
    # Initialize the model
    model = OneLayerModel(duration=15*60)
    # Train the model
    model.train(data_dir)
    # Save the model to the specified path
    save_path = sys.argv[2]
    model.save(save_path)
