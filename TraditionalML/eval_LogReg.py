'''
Reads a pcap and attempts to make a decision about the source device
using the specified model.
'''

import sys
from LogReg import LogRegModel

if __name__ == '__main__':
    # Path to the capture to classify
    pcap_path = sys.argv[1]
    # Initialize the model
    model = LogRegModel(duration=None)
    # Load the model
    model_path = sys.argv[2]
    model.load(model_path)
    # Classify the capture file and print the result
    prediction = model.predict(pcap_path)
    # Print the result
    for p in prediction:
        print(p)
