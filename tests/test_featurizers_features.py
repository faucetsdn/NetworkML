from networkml.featurizers.features import Features


def test_no_func():
    instance = Features()
    instance.run_func('none')


def test_get_columns():
    instance = Features()
    assert instance.get_columns(
        ['foo', 'bar'], [{'foo': 1, 'baz': 3}]) == [{'foo': 1}]
