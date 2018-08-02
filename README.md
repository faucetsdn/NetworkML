# Poseidon: Machine Learning

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://api.travis-ci.com/CyberReboot/PoseidonML.svg?branch=master)](https://travis-ci.com/CyberReboot/PoseidonML)
[![PyPI version](https://badge.fury.io/py/poseidonml.svg)](https://badge.fury.io/py/poseidonml)
[![codecov](https://codecov.io/gh/CyberReboot/PoseidonML/branch/master/graph/badge.svg)](https://codecov.io/gh/CyberReboot/PoseidonML)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/28bb6ce9fa154134b8dda35c5d5d7010)](https://www.codacy.com/app/CyberReboot/PoseidonML?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=CyberReboot/PoseidonML&amp;utm_campaign=Badge_Grade)
[![Docker Hub Downloads](https://img.shields.io/docker/pulls/cyberreboot/poseidonml.svg)](https://hub.docker.com/r/cyberreboot/poseidonml/)

## Overview
Poseidon is a machine learning implementation of our quest to determine
two questions:
  1. what is on the network; and
  2. what is it doing?

For more background and context on our project, please check out
[the Poseidon project](https://www.cyberreboot.org/projects/poseidon/)
page on our website. This repo specifically covers the algorithms and
models we deployed in our project.

While this repository and resulting docker container can be used completely
independently, the code was written to support the Cyber Reboot Vent and
Poseidon projects. See:

- [Vent](https://github.com/CyberReboot/vent) plugins for evaluating
machine learning models on network data; and the
- [Poseidon](https://github.com/CyberReboot/poseidon) SDN project.

This repository contains the components necessary to build a docker container
that can be used for training a number of ML models using network packet
captures (pcaps). The repository includes scripts necessary to do the
training (e.g. "train_OneLayer.py") as well as doing the evaluation once a
model has been trained (e.g. "eval_OneLayer.py")

Additional algorithms and models will be added here as we delve more
deeply into network security profiles via machine learning models. Feel
free to use, discuss, and contribute!


## Plugins

The plugin (i.e., model) we currently have available is **DeviceClassifier**,
which utilizes the OneLayer feedforward technique by default, but the
RandomForest technique used in our Poseidon project is also included.

For more information, check out the respective README file included within
each plugin's folder.


# Installation/Run

Our models can be executed via Vent, Docker, and standalone. We recommend
deployment via Vent in conjunction with Poseidon if you are running an SDN
(software-defined network). Otherwise, we recommend using Docker.

See the respective README files included in the plugin's folder for specific
instructions on deployment.
