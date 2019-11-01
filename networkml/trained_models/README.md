# Machine Learning Models in NetworkML

## Overview
NetworkML performs two separate classifications: role identification and
anomaly detection. Role identification uses either a one-layer neural network
or random forests. Anomaly detection uses stochastic outlier selection.

### One-layer Neural Network
This technique uses a neural network with one hidden layer to do multi-label
classification of device role. For further information on neural networks,
see Francois Chollet's "Deep Learning with Python" published by Manning
Publications in 2018, especially pages 3-116. The neural network model in
networkML uses the Python package scikit-learn. In Cyber Reboot's own
in-house testing, this single layer neural network out-performs random forests
at role classification.

### Random Forests
The random forests model also does multi-label classification of roles. A thorough
description of random forests can be found in Leo Breiman, "Random Forests,"
Journal of Machine Learning Research, Vol. 45, No. 1, 2001. Random Forests
builds on the idea of a decision tree (or a classification and regression
tree aka CART). For information on decision trees, see the 2017 version of
"Classification and Regression Trees" by Leo Breiman and his coauthors published
by Routledge. NetworkML's implementation of decision trees uses the Python
package scikit-learn.

### Stochastic Outlier Selection
Unlike the neural network or random forests models, stochastic outlier selection
is an unsupervised learning approach. For a short description, see a blog post
by the creator of this method, Jeroen Janssens, [here](https://www.datascienceworkshops.com/blog/stochastic-outlier-selection/).
This method detects outliers, a point that has insufficient affinity with the
other data points. This method performs anomaly detection within networkML.
