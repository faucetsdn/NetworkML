from networkml.featurizers.funcs.host import Host
from networkml.pandas_csv_importer import WS_FIELDS


def test_host():
    assert WS_FIELDS
    instance = Host()
