# Machine Learning Models in NetworkML

## Overview

NetworkML performs role identification via supervised machine learning. Although our 
internal analysis compared decision trees, random forests, and neural networks, the public
networkML codebase only includes a neural network (or "deep learning") model.

### Neural Network
Neural networks can be used for supervised machine learning to match patterns in network
traffic with the functional role of a device. For further information on neural networks,
see Francois Chollet's "Deep Learning with Python" published by Manning
Publications in 2018, especially pages 3-116. For more general information on machine 
learning and information security or cybersecurity, see Clarence 
Chio and David Freeman, "Machine Learning & Security," published by O'Reilly
in 2018. The neural network model in networkML uses the Python package scikit-learn. Using
TensorFlow or a similar neural network-specific machine learning package was not necessary
to achieve high levels of performance in our in-house testing.
