from networkml.featurizers.features import Features


def test_no_func():
    instance = Features()
    instance.run_func('none')
