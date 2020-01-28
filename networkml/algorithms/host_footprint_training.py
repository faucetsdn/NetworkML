import numpy as np
import pandas as pd
from sklearn import preprocessing
from sklearn.neural_network import MLPClassifier

def train(input_path):
    """
    This function takes a .csv file of host footprint features--i.e. each
    row is a feature vector for a given host and each column is a feature
    --and trains a model to do business role classification. This function
    returns the trained model. Because the best model is still yet to be
    determined, this method uses only a simple neural network. A future
    version of this function will use a superior model once our research
    group has done experiments with different models and hyperparameter
    optimization.
    
    INPUTS:
    --input_path: the location of the .csv with host footprint features
    
    OUTPUTS:
    --model: a trained model
    --le: a label encoder to transform predictions into business roles
    """
    
    ## Load data from host footprint .csv
    df = pd.read_csv(input_path)
    
    ## Split dataframe into X (the input features or predictors)
    ## and y (the target or outcome or dependent variable)
    X = df.drop("filename", axis=1)
    y = df.filename
    
    ## Extract only role name from strings in y feature
    ## Y feature is the full filename of the .pcap file
    ## but should be only the role name
    
    y = y.str.split("-") ## Split full filename on "-"
                         ## which creates a list
    y = y.str[0] ## Extract first element of list
                 ## which is the role name
        
    ## Normalize X features before training
    scaler = preprocessing.MinMaxScaler()
    X = scaler.fit_transform(X)
    
    ## Convert y into categorical/numerical feature
    le = preprocessing.LabelEncoder()
    y = le.fit_transform(y)
    
    ## Calculate number of categories to predict
    num_categories = len(le.classes_)
    
    ## Train model
    clf = MLPClassifier(solver='sgd',
                        hidden_layer_sizes=(64, 32, num_categories),
                        random_state=1999)
    
    model = clf.fit(X, y)
    
    ## Returns trained model and label encoder
    return model, le