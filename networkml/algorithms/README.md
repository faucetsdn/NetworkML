# Algorithms

Algorithms to classify devices based on their network activity. These algorithms
are the machine learning models used by Poseidon to identify device types (e.g.,
 "developer workstation," "SSH server," etc.). For more information on this model,
 see our blog post [Using machine learning to classify devices on your network](https://blog.cyberreboot.org/using-machine-learning-to-classify-devices-on-your-network-e9bb98cbfdb6)

## Using Docker to evaluate, train, and test

We currently have two different models available on Docker Hub -- RandomForest and
 OneLayer -- tagged `randomforest` and `onelayer`, respectively. OneLayer is used by
 default, however, and is the model included in the `latest` tag. You can build
 eval, test, and training versions of the models by using the Makefile in the root
 directory to call `eval_[modelname]`, `test_[modelname]`, and `train_[modelname]`,
 respectively.

At the moment, the eval versions of the models support one pcap or a directory
 of pcaps. To use this for device classification, you will first need to set a
 $PCAP environment variable before calling the respective `make` command from
 the root directory, like so:

```
export PCAP=[path/to/pcap/file.pcap]
make eval_onelayer
```

By default, `make run` uses the eval_onelayer script.

To use `eval`, you will supply a single PCAP from your local filesystem that can
 be mapped into the Docker container at runtime.  The `train` and `test` functions
 require a directory of PCAP files along with a `label_assignments.json` for
 those PCAPs. If the label_assignments don't line up with the labels of the
 pcaps you wish to train with, you'll need to update it.

Here's an example of implicitly calling `eval_onelayer`:
```
export PCAP=[path/to/file.pcap]
make run
```

And an example of explicitly calling `test_onelayer`:
```
export PCAP=[path/to/pcapdir]
make test_onelayer
```

Use `make help` to see the possible options.

Output is currently JSON to STDOUT, or if training it will output to the models
 directory under networkml.

The logger level is set to INFO by default, if you'd like to override that to
 say DEBUG, you can export the `LOG_LEVEL` variable with the desired value
 before running the make command, like so:
```
export LOG_LEVEL=DEBUG
```

For more information on how to run the models as part of Poseidon, please refer
 to the documentation for [Poseidon](https://github.com/CyberReboot/poseidon).
