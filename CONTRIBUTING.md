# Contributing to NetworkML

Want to hack on NetworkML? Awesome! Here are instructions to get you started.
If you have any questions or find the instructions to be incomplete, please do
open an issue to let us know about it.

## Contribution guidelines

### Pull requests are always welcome

We are always thrilled to receive pull requests and do our best to
process them as fast as possible. Not sure if that typo is worth a pull
request? Do it! We will appreciate it.

If your pull request is not accepted on the first try, don't be
discouraged! If there's a problem with the implementation, hopefully you
received feedback on what to improve.

We're trying very hard to keep NetworkML lean and focused. We don't want it
to do everything for everybody. This means that we might decide against
incorporating a new feature. However, there might be a way to implement
that feature *on top of* NetworkML.

### Create issues...

Any significant improvement should be documented as [a github
issue](https://github.com/CyberReboot/NetworkML/issues) before anybody
starts working on it.

### ...but check for existing issues first!

Please take a moment to check that an issue doesn't already exist
documenting your bug report or improvement proposal. If it does, it
never hurts to add a quick "+1" or "I have this problem too". This will
help prioritize the most common problems and requests.

### Conventions

#### Project structure

The NetworkML project is currently structured to be a collection of
models processing pcap traffic. Each model is contained within its own
folder under the root directory. Code under root's `utils/` folder contains
generic feature extraction and processing from raw pcap files, and can be
reused by any of the models within the collection.

Take the `DeviceClassifier` as an archetype example of one such model.
Our [Poseidon project](https://github.com/CyberReboot/Poseidon) uses this
to identify device roles on the network based on their behavior on the
network. In fact, this classifier contains two different models that can
be used depending on the amount of data available for training -- `OneLayer`
neural network model, and the `RandomForest` model. Each of these models
are contained in their own subdirectories, and a `README` file describes
the usage and requirements of both. Within each model's directory, you'll
find a Dockerfile and the scripts to train, test, and evaluate the models.
Any configurations or options specific to these models are located in the
`opts/` subfolder, and the optional trained models (in the form of
serialized pkl files) are made available in the `models/` subfolder.

Our hope is that by following this structure as much as possible, newer
users can get up to speed more quickly, and models will be easier to
maintain in the long run. However, if you find this too stifling for
your specific model, we will leave it to you to explain the usage,
requirements and structure in your model's `README` file.


#### Submitting a pull request

Fork the repo and make changes on your fork in a feature branch.

Make sure you include relevant updates or additions to documentation and
tests when creating or modifying features.

Pull requests descriptions should be as clear as possible and include a
reference to all the issues that they address.

Code review comments may be added to your pull request. Discuss, then make the
suggested modifications and push additional commits to your feature branch. Be
sure to post a comment after pushing. The new commits will show up in the pull
request automatically, but the reviewers will not be notified unless you
comment.

Before the pull request is merged, make sure that you squash your commits into
logical units of work using `git rebase -i` and `git push -f`. After every
commit the test suite should be passing. Include documentation changes in the
same commit so that a revert would remove all traces of the feature or fix.

Commits that fix or close an issue should include a reference like `Closes #XXX`
or `Fixes #XXX`, which will automatically close the issue when merged.

Add your name to the AUTHORS file, but make sure that the list is sorted and that
your name and email address match the ones you used to make your commits. The
AUTHORS file is regenerated occasionally from the commit history, so a mismatch
may result in your changes being overwritten.

## Decision process

### How are decisions made?

Short answer: with pull requests to the NetworkML repository.

All decisions affecting NetworkML, big and small, follow the same 3 steps:

* Step 1: Open a pull request. Anyone can do this.

* Step 2: Discuss the pull request. Anyone can do this.

* Step 3: Accept or refuse a pull request. A maintainer does this.


### How can I become a maintainer?

* Step 1: learn the code inside out
* Step 2: make yourself useful by contributing code, bugfixes, support etc.

Don't forget: being a maintainer is a time investment. Make sure you will have time to make yourself available.
You don't have to be a maintainer to make a difference on the project!

### What are a maintainer's responsibility?

It is every maintainer's responsibility to:

* 1) Deliver prompt feedback and decisions on pull requests.
* 2) Be available to anyone with questions, bug reports, criticism etc. on NetworkML.

### How is this process changed?

Just like everything else: by making a pull request :)

*Derivative work from [Docker](https://github.com/moby/moby/blob/master/CONTRIBUTING.md).*

### Any questions?

As stated above, if you have any questions or encounter any problems, we recommend checking the
pre-existing issues on the project page. If nothing relates or the discussion turns out to not relate
any longer, feel free to start a new issue. We do our best to respond in a timely fashion and to
keep all discussions open and transparent.
