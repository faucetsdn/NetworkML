# Poseidon: Machine Learning

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://api.travis-ci.com/CyberReboot/PoseidonML.svg?branch=master)](https://travis-ci.com/CyberReboot/PoseidonML)
[![PyPI version](https://badge.fury.io/py/poseidonml.svg)](https://badge.fury.io/py/poseidonml)
[![codecov](https://codecov.io/gh/CyberReboot/PoseidonML/branch/master/graph/badge.svg)](https://codecov.io/gh/CyberReboot/PoseidonML)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/28bb6ce9fa154134b8dda35c5d5d7010)](https://www.codacy.com/app/CyberReboot/PoseidonML?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=CyberReboot/PoseidonML&amp;utm_campaign=Badge_Grade)
[![Docker Hub Downloads](https://img.shields.io/docker/pulls/cyberreboot/poseidonml.svg)](https://hub.docker.com/r/cyberreboot/poseidonml/)

## Overview
PoseidonML is the Machine Learning portion of our (Poseidon) project that
attempts to answer two questions:
  1. what type of device is in this packet capture (pcap)?
  2. is it behaving in an expected way?

This repo is for the ML portion of the project, which can also be used
in a "standalone" mode from the CLI. For more background and context on
the macro project, please check out [the Poseidon project](https://www.cyberreboot.org/projects/poseidon/)
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
training as well as doing the evaluation once a model has been trained. These
can be run from a shell once `poseidonml` is installed as a package or run in a
Docker container using the `networkml` script.

Additional algorithms and models will be added here as we delve more
deeply into network security profiles via machine learning models. Feel
free to use, discuss, and contribute!


## Algorithms

The algorithms (i.e., untrained model) we currently have available are the
OneLayer feedforward technique (default), the RandomForest technique as an
alternative classifier and the SoS technique which is used for detecting
abnormal behavior.

For more information, check out the respective README file included within
the `networkml/algorithms` folder.


# Installation/Run

Our models can be executed via Vent, Docker, and in a standalone manner on a
Linux host. We recommend deployment via Vent in conjunction with Poseidon if you
are running an SDN (software-defined network). Otherwise, we recommend using Docker.

See the [README](https://github.com/CyberReboot/PoseidonML/blob/master/networkml/algorithms/README.md) file included in the `networkml/algorithms` folder for specific instructions on deployment.


# Develop/Standalone installation

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
