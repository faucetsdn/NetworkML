# v0.2.3 (2018-12-14)

 - upgraded pytest to 4.0.2
 - upgraded scikit-learn to 0.20.1
 - improved README documentation
 - upgraded redis to 3.0.1
 - added pcap directory support
 - re-enabled the behavior model
 - includes the trained behavior model
 - fixed hardcoded onelayer pickle file in randomforest
 - fixed missing labels
 - simplified rabbit connection
 - replaced deprecated randomized logistic regression with random forest

# v0.2.2 (2018-10-22)

 - upgraded pytest to 3.9.1
 - fixed a NoneType error when multiplying
 - fixed an issue where the config file wasn't being read properly
 - abstracted away the code to read the config file into one place

# v0.2.1 (2018-10-02)

 - lots of cleanup of duplicated code
 - upgraded tensorflow to 1.11.0
 - upgraded scikit-learn to 0.20.0
 - updated the model

# v0.2.0 (2018-09-22)

 - moved a bunch of duplicated code into common utils

# v0.1.9 (2018-09-21)

 - fixed issue where results were not getting sent to rabbitmq or stored in redis
 - cleaned up cruft in OneLayer Eval
 - moved OneLayer Eval code into a class to reduce duplication

# v0.1.8 (2018-09-10)

 - upgraded pytest to 3.8.0
 - upgraded pytest-cov to 2.6.0
 - upgraded tensorflow to 1.10.1
 - made all print statements logger statements
 - sends messages to rabbitmq now even if not enough sessions
 - stores normal/abnormal results in redis now
 - fixed performance issue where evaluation would take a long time
 - updated the model

# v0.1.7 (2018-08-24)

 - upgraded pytest to 3.7.2
 - upgraded numpy to 1.15.1

# v0.1.6 (2018-08-10)

 - updated model
 - upgraded pytest to 3.7.1
 - upgraded scikit-learn to 0.19.2
 - linting

# v0.1.5 (2018-07-27)

 - fixes pairs issue when checking private addresses
 - fixes the models path for running in a container
 - improve dockerfile builds
 - upgraded pika to 0.12.0
 - upgraded scipy to 1.1.0
 - upgraded numpy to 1.14.5
 - upgraded tensorflow to 1.9.0
 - fixed vent template
 - added some initial tests
 - re-trained the onelayer model with improved accuracy
 - reduced the number of labels for onelayer to 6
 - improvements for developing on poseidonml

# v0.1.4 (2018-07-13)

 - initial utility release
