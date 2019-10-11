# Config Files Explained

## Overview
Config Files define the variables that the NetworkML model will monitor, how 
those variables are analyzed to determine device types operating on a network, 
and what are the typical operating characteristics of common network devices.  

## Config 
Establishes limits on variables used by the code to identify types of devices on various networks. 
Also consolidates the location of these variables, allowing for ease of customization.

### Config File Value Definitions

1. batch size
2. duration
3. look time
4. max port
6. rnn size
7. session threshhold
8. source identifier
9. state size
10. threshhold
11. time constant

## Label Assignments
Defines the various device classes that the model will identify on a network. The model builds 
a profile of typical behavior of the various device classes and can identify when these devices 
are acting abnormally. This can be customized to cover the specific device classes needed by individual users.
