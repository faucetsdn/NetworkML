import numpy as np
import pandas as pd
import json
from sklearn import preprocessing

def predict(input_path, model, label_encoder, scaler_fitted):
    """
    This function takes a csv of features at the host footprint level and then makes
    a role prediction for each row. The output is the top three roles.

    INPUTS:
    --input_path: the location of the .csv with host footprint features (correct assumption?)
    --model: a trained model
    --label_encoder: a mapping of numeric ouput to roles?
    
    OUTPUTS:
    --prediction: top three roles for each host and the associated probability of each role
    (in json format)
    """
    
    ## Load data from host footprint .csv
    df = pd.read_csv(input_path)
    
    ## Check if there is greater than 1 row, there should
    ## only be one row
    if df.shape[0] > 1:
        
        pass
        ## log warning
        ## TODO: JOHN SPEED NEEDS HELP USING THE PROPER SYNTAX
        #logging.error(f'More than one row found in predict_input csv')      
    
    ## Split dataframe into X (the input features or predictors)
    ## and y (the target or outcome or dependent variable)
    ## This drop function should work even if there is no column
    ## named filename
    X = df.drop("filename", axis=1)

    ## Normalize X features before training
    scaler = preprocessing.MinMaxScaler()
    X = scaler_fitted.transform(X) ## Use already fitted scaler
    
    ## Make model predicton - Will return a vector of values
    predictions = model.predict_proba(X)[0] ## Convert list with one list
                                            ## item into just one list

    ## Output JSON of top three roles and probabilities
    
    ## These operations do NOT create a sorted list
    ## NOTE: To change the number of roles for which you want a prediction
    ## change the number number in the argpartition line of code
    ind = np.argpartition(predictions, 3)[-3:] ## Index of top three roles
    labels = label_encoder.inverse_transform(ind) ## top three role names
    probs = predictions[ind] ## probability of top three roles
    
    ## Put labels and probabilities into list
    role_list = [(k, v) for k,v in zip(labels, probs)]
    
    ## Sort role list by probabilities
    role_list_sorted = sorted(role_list, key=lambda x: x[1], reverse=True)

    ## Place roles and probabilities in json
    role_predictions = json.dumps(role_list_sorted)
    
    return role_predictions