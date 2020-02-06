from networkml.algorithms.host_footprint_predict import predict

def test_predict():
    """
    Test basic functionality of the prediction function -- Predict the
    top business roles of a given device
    """

    ## Import training function to create inputs for predict function
    from networkml.algorithms.host_footprint_training import train

    ## A csv of featurized data
    input_file = './tests/combined.csv'

    ## Create model, label encoder, and a fitted scaler from the test dataset
    model, label_encoder, scaler_fitted = train(input_file)

    predict(input_file, model, label_encoder, scaler_fitted)