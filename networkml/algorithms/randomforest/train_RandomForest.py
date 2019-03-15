'''
Trains and saves an instance of the random decision forest model on the
data directory specified by the '-P' argument ('/pcaps' by default). The
model is saved to a location specified by the -w parameter
('models/RandomForestModel' by default).
'''
import argparse

from poseidonml.config import get_config
from poseidonml.Model import Model
from sklearn.ensemble import RandomForestClassifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', '-c', default='opts/config.json',
                        help='model\'s config file')
    parser.add_argument('--pcaps', '-P', default='/pcaps',
                        help='pcap directory to train on (e.g., /pcaps)')
    parser.add_argument('--save', '-w', default='models/RandomForestModel.pkl',
                        help='path to save model (e.g., models/RandomForestModel.pkl)')

    args = parser.parse_args()

    # Load model params from config
    config = get_config(args.config)
    duration = config['duration']
    labels = config['labels']

    # Get the data directory
    data_dir = args.pcaps

    m = RandomForestClassifier(
        n_estimators=100,
        min_samples_split=5,
        class_weight='balanced'
    )

    # Initialize the model
    model = Model(
        duration=duration,
        labels=labels,
        model=m,
        model_type='RandomForest'
    )
    # Train the model
    model.train(data_dir)
    # Save the model to the specified path
    model.save(args.save)


if __name__ == '__main__':
    main()
