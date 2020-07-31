# Device Functional Role ID via Machine Learning and Network Traffic Analysis

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Build Status](https://github.com/iqtlabs/networkml/workflows/test/badge.svg)
[![PyPI version](https://badge.fury.io/py/networkml.svg)](https://badge.fury.io/py/networkml)
[![codecov](https://codecov.io/gh/IQTLabs/NetworkML/branch/master/graph/badge.svg)](https://codecov.io/gh/IQTLabs/IQTLabs)
[![Docker Hub Downloads](https://img.shields.io/docker/pulls/iqtlabs/networkml.svg)](https://hub.docker.com/r/iqtlabs/networkml/)

## Overview
NetworkML is the machine learning portion of our [Poseidon](https://github.com/IQTLabs/poseidon) project. The model in networkML classifies each device into a functional role via machine learning models trained on features derived from network traffic. "Functional role" refers to the authorized administrative purpose of the device on the network and includes roles such as printer, mail server, and others typically found in an IT environment. Our internal analysis suggests networkML can achieve accuracy, precision, recall, and F1 scores in the high 90's when trained on devices from your own network. Whether this performance can transfer from IT environment to IT environment is an active area of our research.

NetworkML can be used in a "standalone" mode from the command line interface. For more background and context on the macro project, please check out [the Poseidon project](https://www.cyberreboot.org/projects/poseidon/) page on our website. This repository specifically covers the output, inputs, data processing, and machine learning models we deploy in networkML.

While this repository and resulting docker container can be used completely independently, the code was written to support the IQT Labs Poseidon project. See:

- [Poseidon](https://github.com/IQTLabs/poseidon) SDN project.

This repository contains the components necessary to build a docker container that can be used for training a number of ML models using network packet captures (PCAPs). The repository includes scripts necessary to do training, testing, and evaluation. These can be run from a shell once `networkml` is installed as a package or run in a Docker container using the `networkml` script.

Feel free to use, discuss, and contribute!

## Model Output
NetworkML predicts the functional role of network-connected device via network traffic analysis and machine learning.

Admittedly subjective, the term "role" refers to the authorized administrative purpose of the device on the network. NetworkML in its default configuration has twelve roles: active directory controller, administrator server, administrator workstation, confluence server, developer workstation, distributed file share, exchange server, graphics processing unit (GPU) laptop, github server, public key infrastructure (PKI) server, and printer. This typology reflects the network-connected devices in the data we used to train the model. Other networks will lack some of these roles and might include others. Consequently, organizations that wish to use networkML might have to adapt the model outputs for their specific organization.

## Model Inputs
NetworkML's key input is the network traffic for a single device. By network traffic for a single device, we mean all packets sent and received by that device over a given time period. For reliable results, we recommend at least fifteen minutes of network traffic. Poseidon, the larger project of which networkML is only a part, performs the necessary packet pre-processing to produce pcap's containing all network traffic to and from a single device. If you are using networkML in a standalone manner, the pcap files must all follow a strict naming convention: DeviceName-deviceID-time-duration-flags.pcap. For example, ActiveDirectoryController-labs-Fri0036-n00.pcap refers to a pcap from an active directory controller taken from a user named labs on a Friday at 00:36. The flag field does not currently have any significance.

It is worth noting that networkML uses only packet header data in its models. NetworkML does not use data from the packet payload. Relying only on packet header data enables networkML to avoid some privacy-related issues associated with using payload data and to create (hopefully) more generalizable and more performant models.

## Data Processing

## Algorithms

NetworkML uses a feedforward neural network from the scikit-learn package. The model is trained using 5-fold cross validation in combination with a simple grid-search of the hyper-parameter space.


# Installation/Run

Our models can be executed via Docker and in a standalone manner on a Linux host. We recommend deployment via Poseidon if you are running an SDN (software-defined network). Otherwise, we recommend using Docker.

See the [README](https://github.com/IQTLabs/NetworkML/tree/master/networkml/trained_models) file included in the `networkml/trained_models` folder for specific instructions on deployment.

# Develop/Standalone Installation

Note: This project uses absolute paths for imports, meaning you'll either need to modify your `PYTHONPATH` to something like this from the project directory:
```
export PYTHONPATH=$PWD/networkml:$PYTHONPATH
```
Alternatively, simply running `pip3 install .` from the project directory after making changes will update the package to test or debug against.

This package is set up for anaconda/miniconda to be used for package and environment
management if desired. Assuming you have the latest install (as of this writing, we have been using
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
