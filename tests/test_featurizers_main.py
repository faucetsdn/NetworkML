from networkml.featurizers.features import Features
from networkml.featurizers.main import Featurizer


def test_no_path():
    instance = Featurizer()
    result = instance.import_class('foo', None)
    assert result == None


def test_run_all_funcs():
    instance = Featurizer()

    class TestClass(Features):

        @staticmethod
        def test_feature1(rows, _srcmacid):
            for row in rows:
                return [{'test1': row['test1']}]

        @staticmethod
        def test_feature2(rows, _srcmacid):
            for row in rows:
                return [{'test2': row['test2']}]

    tc = TestClass()

    results = instance.run_all_funcs(
        [('test_feature1', 'test_feature1'),
            ('test_feature2', 'test_feature2')], [],
        [(tc, 'test_feature1'), (tc, 'test_feature2')],
        [{'test1': 99, 'test2': 123}],
        True)
    assert results == [[{'test1': 99}], [{'test2': 123}]]

    results = instance.run_all_funcs(
        [], [], [], [{'test1': 99, 'test2': 123}], True)
    assert results == []
