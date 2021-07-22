import pandas as pd
from networkml.featurizers.features import Features


def test_quantile_nullable_int():
    # TODO: https://github.com/pandas-dev/pandas/issues/42626
    # TODO: migrate all tests to unittest class/assert method style.
    df = pd.DataFrame([{'x': 1}, {'x': 0}], dtype=pd.Int64Dtype())
    assert df['x'].quantile(0.75)  # nosec


def test_no_func():
    instance = Features()
    instance.run_func('none')


def test_get_columns():
    instance = Features()
    assert instance.get_columns(
        ['foo', 'bar'], [{'foo': 1, 'baz': 3}]) == [{'foo': 1}]
