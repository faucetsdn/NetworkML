# Configuration Files Explained

## Overview
These configuration files define the variables that the NetworkML model will
monitor, how those variables are computed, and how the machine learning model
should be executed.

## Config
This file consolidates these variables into one location to make future
adjustments to these variable values easier.

### Configuration File Value Definitions

1. Batch size - The number of training examples in a single pass. This is a
parameter used to train the stochastic outlier selection model.
2. Duration - This variable defines the time window of network traffic for which to compute information on features.
3. Look time - This variable defines (in seconds) the minimum time between
re-investigation of a potentially suspicious device.
4. Max Port - This variable sets the maximum port number for feature creation.
All ports below this number are included as part of the feature creation process.
1024 is the value because these are the so-called well-known ports, i.e. the
most common ports.
6. RNN Size - This variable is a parameter in the stochastic outlier selection
model.
7. Session Threshold - This is the minimum number of packets needed for a
session to be included in analysis.
8. Source Identifier - Variable for how networkML determines what device is
initiating a session.
9. State Size - A variable for the number of neurons (or nodes) in the neural
network model.
10. Threshold - A percentage threshold for the confidence needed to deem a session
bin abnormal. 99 is an arbitrary cut point.
11. Time Constant - This variable is used as part of an operation to take a
moving average. The value 86,400 is the number of seconds in a day. (60 * 60 * 24)

## Label Assignments
These labels define the various device classes that the model will identify on a network. The model builds a profile of typical behavior of these device classes and can identify when these devices are acting abnormally, e.g. when a printer is
acting abnormally. These labels can be customized to the specific device classes needed by individual users.
