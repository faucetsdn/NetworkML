# Machine Learning for Computer Network Traffic

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://api.travis-ci.com/CyberReboot/NetworkML.svg?branch=master)](https://travis-ci.com/CyberReboot/NetworkML)
[![PyPI version](https://badge.fury.io/py/networkml.svg)](https://badge.fury.io/py/networkml)
[![codecov](https://codecov.io/gh/CyberReboot/NetworkML/branch/master/graph/badge.svg)](https://codecov.io/gh/CyberReboot/NetworkML)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/28bb6ce9fa154134b8dda35c5d5d7010)](https://www.codacy.com/app/CyberReboot/NetworkML?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=CyberReboot/NetworkML&amp;utm_campaign=Badge_Grade)
[![Docker Hub Downloads](https://img.shields.io/docker/pulls/cyberreboot/networkml.svg)](https://hub.docker.com/r/cyberreboot/networkml/)

## Overview
NetworkML is the machine learning portion of our [Poseidon](https://github.com/CyberReboot/poseidon)
project. The models in networkML answer two questions:
  1. What is the role of the device in a particular packet capture (PCAP)?
  2. Given that device's role, is that device acting properly or anomalously?

NetworkML can also be used in a "standalone" mode from the command line interface.
For more background and context on the macro project, please check out
[the Poseidon project](https://www.cyberreboot.org/projects/poseidon/)
page on our website. This repository specifically covers the outputs, inputs,
data processing, and machine learning models we deploy in networkML.

While this repository and resulting docker container can be used completely
independently, the code was written to support the Cyber Reboot Vent and
Poseidon projects. See:

- [Vent](https://github.com/CyberReboot/vent) plugins for evaluating
machine learning models on network data; and the
- [Poseidon](https://github.com/CyberReboot/poseidon) SDN project.

This repository contains the components necessary to build a docker container
that can be used for training a number of ML models using network packet
captures (PCAPs). The repository includes scripts necessary to do training,
testing, and evaluation. These can be run from a shell once `networkml` is
installed as a package or run in a Docker container using the `networkml`
script.

Additional features and models will be added here as we delve more
deeply into network security profiles via machine learning models. Feel
free to use, discuss, and contribute!

## Model Outputs
NetworkML currently produces two outputs for a given device's network traffic.

The first output is the device's role. Admittedly subjective, the term "role"
refers to a label for a group of devices that share a set of networking functions.
For example, a device can be a printer; all printers, assuming proper functioning,
share a set of networking functions. NetworkML in its default configuration has
twelve roles: active directory controller, administrator server, administrator
workstation, confluence server, developer workstation, distributed file share,
exchange server, graphics processing unit (GPU) laptop, github server, public
key infrastructure (PKI) server, and printer. NetworkML also contains a
"unknown" label for devices for which the model cannot confidently predict its
role. This typology reflects the network components in the data we used to train
the model. Other networks will lack some of these roles and will include others.
Consequently, organizations that wish to use networkML might have to adapt the
model outputs for their specific organization. We at Cyber Reboot consider the
appropriate role outputs to be an active area of research, even for our own
network.

The second model output is a determination whether a given device's network
traffic--based on that device's role--is normal or anomalous. For example,
the model can assess whether a particular device identified as a printer has
network traffic similar to other printers.

## Model Inputs
NetworkML's key input is the network traffic for a single device. By network
traffic for a single device, we mean all packets sent and received by that
device over a given time period. For reliable results, we recommend at least
fifteen minutes of network traffic. Poseidon, the larger project of which
networkML is only a part, performs the necessary packet pre-processing to
produce pcap's containing all network traffic to and from a single device. If
you are using networkML in a standalone manner, the pcap files must all follow
a strict naming convention: DeviceName-deviceID-time-duration-flags.pcap. For
example, ActiveDirectoryController-labs-Fri0036-n00.pcap refers to a pcap from
an active directory controller taken from a user named labs on a Friday at
00:36. The flag field does not currently have any significance.

It is worth noting that networkML uses only packet header data in its models.
NetworkML does not use data from the packet payload.

## Data Processing

There are six high-level data processing when using networkML for prediction.

Step #1 (Convert pcap to sessions): The pcap file that contains all network
conversations for a single device is converted into sessions. A session is all
packets sent and received between one internet protocol (IP) address and source
port combination and another IP address and source port.

Step #2 (Extract features from sessions): All sessions are then converted into
a statistical representation (a vector of values). There are currently 4,104
features for each session. There are feature sets for both the packets
that a device receives and the packets that a devices sends. These features
include a percentage of the packets that use each source port or destination
port from 1 to 1024 (the so-called well-known ports), the percentage of packets
that use transmission control protocol (TCP), user datagram protocol (UDP), or
internet control message protocol (ICMP), and the percentage of packets that are
part of an external session. To recap, there are 1024 source port features, 1024
destination port features, three protocol features, one external session feature,
for both incoming and outgoing packets for a host, so (1024 + 1024 + 3 + 1) * 2
= 4,104. Cyber Reboot also considers this aspect of networkML to be an active
area of research. We are considering potential additional features.

Step 3 (Predict role for each session): The model makes a prediction of role
type for each session. The models are further described in the algorithms
section below.

Step 4 (Average role predictions): All role predictions are then averaged
across the sessions for one device.

Step 5 (Output top three role predictions): For each device, the model then
outputs the three most likely roles.

Step 6 (Given device role, do anomaly detection): The model then outputs--
based on the predicted role--whether the device is acting normally or
anomalously for that role.

We recognize that this description is light on details, especially related to
anomaly detection. We will update the description in the coming months.

## Algorithms

The algorithms (i.e., untrained models) we currently have available are the
one-layer feedforward neural network (default), random forests, and the stochastic
outlier selection (SOS) model. The neural network and the random forests models
are used for role identification. The SOS model is used for anomaly detection.

For more information, check out the respective README file included within
the `networkml/algorithms` folder.

# Installation/Run

Our models can be executed via Vent, Docker, and in a standalone manner on a
Linux host. We recommend deployment via Vent in conjunction with Poseidon if you
are running an SDN (software-defined network). Otherwise, we recommend using Docker.

See the [README](https://github.com/CyberReboot/NetworkML/blob/master/networkml/algorithms/README.md) file included in the `networkml/algorithms` folder for specific instructions on deployment.

# Develop/Standalone Installation

This package is set up for anaconda/miniconda to be used for package and environment
management. Assuming you have the latest install (as of this writing, we have been using
conda 4.5.12), set up the environment by performing the following:
 1. Ensure that the CONDA_EXE environment variable has been set. If `echo $CONDA_EXE`
returns empty, resolve this by `export CONDA_EXE=$_CONDA_EXE` in your bash shell.
 2. Run `make dev` to set up the environment
 3. Run `conda activate posml-dev` to begin.

You can remove the dev environment via standard conda commands:
 1. Run `conda deactivate`
 2. Run `conda env remove -y -n posml-dev`

For more information about using conda, please refer to their
[user documentation](https://conda.io/projects/conda/en/latest/user-guide/getting-started.html).
