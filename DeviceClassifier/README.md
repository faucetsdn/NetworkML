# DeviceClassifier

Plugin to classify devices based on their network activity. This plugin is the
 original machine learning model used by Poseidon to identify device types (e.g.,
 "developer workstation," "SSH server," etc.). For more information on this model,
 see our blog post [Using machine learning to classify devices on your network](https://blog.cyberreboot.org/using-machine-learning-to-classify-devices-on-your-network-e9bb98cbfdb6)

## Using Docker to evaluate, train, and test

_**Note:** we are aware of issues that currently render the RandomForest model
 unuseable, and we are working to fix this as soon as possible. You can check the
 progress on this fix via [issue #104](https://github.com/CyberReboot/PoseidonML/issues/104)._

We currently have two different models available on Docker Hub -- RandomForest and
 OneLayer -- tagged `randomforest` and `onelayer`, respectively. OneLayer is used by
 default, however, and is the model included in the `latest` tag. You can build
 eval, test, and training versions of the models by using the Makefile in the root
 directory to call `eval_[modelname]`, `test_[modelname]`, and `train_[modelname]`,
 respectively.

At the moment, the eval versions of the models support one pcap at a time. To use
 this for device classification, you will first need to set a $PCAP environment
 variable before calling the respective `make` command from the root directory, like
 so:

```
export PCAP=[path/to/pcap/file.pcap]
make eval_onelayer
```
By default, `make run` uses the eval_onelayer script.

To use `eval`, you will supply a single PCAP from your local filesystem that can
 be mapped into the Docker container at runtime.  The `train` and `test` functions
 require a directory of PCAP files along with a `label_assignments.json` for
 those PCAPs. If the label_assignments don't line up with the ones in `config.json`
 under the `opts` directory, be sure to add them there as well.  Currently the
 models require that the number of labels in `config.json` be exactly 21, don't
 worry if you don't have data to train all of the labels, but note that you need
 to keep 21 there, even if you don't use them all. Models will be mapped to `/tmp/models`.

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

Output is currently JSON to STDOUT.

For more information on how to run the models as part of Poseidon, please refer
 to the documentation for [Poseidon](https://github.com/CyberReboot/poseidon).
