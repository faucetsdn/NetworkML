'''
Trains and saves an instance of the logistic regression model on the data
directory specified as the first argument and save it to the file specified by
the second argument
'''
import sys
from LogReg import LogRegModel

if __name__ == '__main__':
    # Get the data directory from the first argument
    data_dir = sys.argv[1]
    # Initialize the model
    model = LogRegModel(duration=3600)
    # Train the model on the data directory
    model.train(data_dir)
    # Save the model to
    save_path = sys.argv[2]
    model.save(save_path)
