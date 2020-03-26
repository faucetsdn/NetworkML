from networkml.featurizers.features import Features


def test_no_func():
    instance = Features()
    instance.run_func('none')


def test_stat_row_field():
    instance = Features()
    assert instance._stat_row_field(max, 'notthere', lambda: [{'foo': 1, 'baz': 3}]) == 0
    assert instance._stat_row_field(max, 'foo', lambda: [{'foo': 1, 'baz': 3}, {'foo': 99, 'baz': 3}]) == 99
