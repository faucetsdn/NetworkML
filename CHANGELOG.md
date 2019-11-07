
# v0.4.1 (2019-11-07)

- updated numpy to 1.17.3
- updated pytest to 5.2.2
- Added documentation
- Added support for additional labels and filenames

# v0.4.0 (2019-10-24)

- Updated pytest-cov
- Updated pytest
- Updated redis
- Added more documentation and tests
- Updated the python image for the Dockerfile

# v0.3.9 (2019-10-02)

- Updated pytest to 5.2.0
- Updated tensorflow to 2.0.0
- Fixed up old code using tensorflow1 to work with tensorflow2

# v0.3.8 (2019-09-12)

- Updated pytest to 5.1.2
- Updated numpy to 1.17.2
- Fixed make help

# v0.3.7 (2019-08-30)

- Updated redis to 3.3.8
- Updated pytest to 5.1.1

# v0.3.6 (2019-08-15)

- Updated redis to 3.3.7
- Redis is now optional
- RabbitMQ is now configurable, and has a cleaned up message format
- Retrained models against numpy 1.17.0 and scikit-learn 0.21.3

# v0.3.5 (2019-08-02)

- Updated pika to 1.1.0
- Got rid of outdated linux headers
- Updated redis to 3.3.4

# v0.3.4 (2019-07-11)

- Updated to python3.7
- Updated models
- Updated tensorflow to 1.14.0
- Updated pytest to 5.0.1

# v0.3.3 (2019-06-13)

- Updated models and included printers
- Renamed PoseidonML to NetworkML
- Updated pytest to 4.6.3

# v0.3.2 (2019-05-31)

- Updated numpy to 1.16.3
- Updated pytest-cov to 2.7.1
- Updated pytest to 4.5.0
- Reduce places that Tensorflow is imported
- Made it possible to run classifications on CPUs that don't support AVX

# v0.3.1 (2019-04-18)

- Updated Tensorflow imports for new deprecations
- Updated pika to 1.0.1
- Removed a bunch of duplicated code to keep the code base cleaner
- Added a bunch of tests to get coverage up to 90%
- Updated pytest to 4.4.1
- Removed the use of md5 and replaced it with sha224

# v0.3.0 (2019-04-04)

- Major rewrite and restructuring of the code base, but same functionality

# v0.2.10 (2019-03-22)

 - Changed the default for Rabbit to not be used
 - Changed the environment variable for Rabbit from SKIP_RABBIT to RABBIT
 - Improved logging output for summarizing evaluation results of multiple PCAPs
 - Updated versions of pika, pytest, redis, and scikit-learn
 - Fixed a bug that was preventing training the SoSModel
 - Added some more test coverage
 - Updated the trained models and labels

# v0.2.9 (2019-03-08)

 - Updated tensorflow from 1.12.0 to 1.13.1.
 - Updated numpy from 1.16.1 to 1.16.2.
 - Miscellaneous error checking and spacing corrections.

# v0.2.8 (2019-02-22)

 - Updated pytest to 4.3.0 from 4.2.0.
 - Cleaned up some code issues as pointed out by Codacy.
 - Minor miscellaneous bugfixes to support running training natively.

# v0.2.7 (2019-02-09)

 - Provided a way to run DeviceClassifier training and testing scripts from command line.
 - Cleaned up some unused code and consolidated common operations into utils and model class.
 - Fixed issue where Makefile built the OneLayer training container when building the test one.
 - Updated redis to 3.1.0
 - Updated numpy to 1.16.1

# v0.2.6 (2019-01-25)

 - Updated numpy to 1.16.0
 - Updated pika to 0.13.0
 - Included a conda yml file for a standalone/dev environment, and new Makefile options to build it.

# v0.2.5 (2019-01-11)

 - models have been retrained to fix a warning about invalid results when evaluating a pcap
 - some unused code and module has been removed
 - upgraded pytest to 4.1.0 and pytest-cov to 2.6.1

# v0.2.4 (2018-12-21)

 - upgraded scikit-learn to 0.20.2
 - removed scipy
 - cleaned up requirements.txt and setup.py
 - fixed issue where redis was throwing error when saving decisions
 - fixed error in eval_onelayer that was using nonexistent key
 - Make train/eval/test process consistent for all models
 - Fixed path error specific to python 3.5 that occurred when processing PCAP files
 - PCAP directories can now be used when running model evals

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
