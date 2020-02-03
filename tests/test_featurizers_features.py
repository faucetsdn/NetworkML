from networkml.featurizers.features import Features


def test_no_func():
    instance = Features()
    instance.run_func('none')


def test_get_columns():
    instance = Features()
    assert instance.get_columns(['foo', 'bar'], [{'foo': 1, 'baz': 3}]) == [{'foo': 1}]


def test_stat_row_field():
    instance = Features()
    assert instance._stat_row_field(max, 'notthere', [{'foo': 1, 'baz': 3}]) == 0
    assert instance._stat_row_field(max, 'foo', [{'foo': 1, 'baz': 3}, {'foo': 99, 'baz': 3}]) == 99


def test_tshark_input_mac():
    instance = Features()
    # 1 appears the most on both sides.
    assert instance._tshark_input_mac(
        [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]) == 1


def test_select_mac_direction():
    rows = [{'eth.src': 1, 'eth.dst': 2}, {'eth.src': 2, 'eth.dst': 1}, {'eth.src': 1, 'eth.dst': 99}]
    instance = Features()
    assert [{'eth.dst': 1, 'eth.src': 2}] == list(instance._select_mac_direction(rows, output=False))
    assert [{'eth.dst': 2, 'eth.src': 1}, {'eth.dst': 99, 'eth.src': 1} == list(instance._select_mac_direction(rows, output=True))
