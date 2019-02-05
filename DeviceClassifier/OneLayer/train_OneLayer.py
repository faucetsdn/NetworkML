'''
Trains and saves an instance of the one layer feedforward model on the
data directory specified by the '-P' argument ('/pcaps' by default).  The 
model is saved to a location specified by the -w parameter 
('models/OneLayerModel' by default).
'''
import argparse
import sys

from poseidonml.config import get_config
from poseidonml.Model import Model
from sklearn.neural_network import MLPClassifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', '-c', default='opts/config.json',
                        help='model\'s config file')
    parser.add_argument('--pcaps', '-P', default='/pcaps',
                        help='pcap directory to train on (e.g., /pcaps)')
    parser.add_argument('--save', '-w', default='models/OneLayerModel.pkl',
                        help='path to save model (e.g., models/OneLayerModel.pkl)')
                       
    args = parser.parse_args()

    # Load model params from config
    config = get_config(args.config)
    duration = config['duration']
    hidden_size = config['state size']
    labels = config['labels']

    # Get the data directory
    data_dir = args.pcaps

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
    model.save(args.save)

if __name__ == '__main__':
    main()
