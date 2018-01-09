# Poseidon: Machine Learning - Phase II

## Overview
This repository contains the components necessary to build a docker container that can be used for training a number of ML models using network packet captures (pcaps).  The repository includes scripts necessary to do the training (e.g. "train_OneLayerModel.py") as well as doing the evaluation once a model has been trained (e.g. "eval_OneLayer.py")  

While this repository and resulting docker container can be used completely independently, this code was written to support the Cyber Reboot Vent and Poseidon projects. See:

[Vent](https://github.com/CyberReboot/vent) plugins for evaluating
machine learning models on network data as part of the
[Poseidon](https://github.com/CyberReboot/poseidon) SDN project.

## Plugins
The current supported plugins are:

### NodeClassifier
Plugin for traffic classification to determine device types and their behavior.

## Using Docker to evaluate, train, and test
Currently there are two different models that can be used, by default
RandomForest will be used and is the model for the `latest` tag.  There are
tags for both models `onelayer` and `randomforest`.  Arguments can be passed in
to change if it should `eval`, `train`, or for `testing`.  By default it will
`eval` if no argument is supplied.

For `eval` you'll supply a single PCAP from your local filesystem that can be
mapped into the Docker container at runtime.  For `train` and `testing` you'll
supply a directory of PCAP files along with a `label_assignments.json` for
those PCAPs.  Additionally you'll map a place to save the models.

Here's an example for implicit `eval` and implicit `randomforest`:

```
docker run -v <path_to_local_pcap_file>:/pcaps/eval.pcap lab41/poseidonml
```

Here's an example of explicit `eval` and explicit `onelayer`:

```
docker run -v <path_to_local_pcap_file>:/pcaps/eval.pcap lab41/poseidonml:onelayer eval
```

Here's an example of explicit `train` and implicit `randomforest`:

```
docker run -v <path_to_local_pcaps>:/pcaps -v <path_to_save_models:/models lab41/poseidonml train
```

Here's an example of explicit `testing` and explicit `randomforest`:

```
docker run -v <path_to_local_pcaps>:/pcaps -v <path_to_save_models:/models lab41/poseidonml:randomforest testing
```

## Rough Getting Started
1. Get the bits: git clone https://github.com/Lab41/PoseidonML.git
2. Build the docker container:
    a. "cd PoseidonML/NodeClassifier/"
    b. "./build-docker.sh"
3. Collect your training pcaps and put them into a directory (tcpdump is what we usually use)
4. Launch the docker container: "docker run -it -v /home/<user>/PoseidonML:/app poseidonml bash"
5. create config file called “label_assignments.json” in pcaps dir
    - It maps pcap files to class name, similar to [label_assignments.json sample](https://github.com/Lab41/PoseidonML/blob/master/NodeClassifier/data/label_assignments.json).
    - Classes should be defined in the config.json file label list [config.json](https://github.com/Lab41/PoseidonML/blob/master/NodeClassifier/config.json)
6. To train a model: python train_OneLayerModel.py &lt;pcapdir&gt; &lt;filename&gt;.pickle
7. Once trained, to evaluate using that model: python eval_OneLayer.py &lt;pcapdir&gt; &lt;filename&gt;.pickle
8. If model to be used with Poseidon, then put the model.picke in /tmp/models/ directory. 

Output is currently JSON to STDOUT
