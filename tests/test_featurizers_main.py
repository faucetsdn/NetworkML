from networkml.featurizers.main import Featurizer


def test_no_path():
    instance = Featurizer()
    result = instance.import_class('foo', None)
    assert result == None
