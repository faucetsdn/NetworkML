from setuptools import setup

setup(
    name='poseidonml',
    version='0.2.9',
    packages=['poseidonml'],
    package_dir={'poseidonml': 'utils'},
    package_data={'poseidonml': ['models/*']},
    install_requires=['numpy==1.16.2', 'pika==0.13.0', 'redis==3.2.0',
                      'scikit-learn==0.20.2', 'tensorflow==1.13.1'],
    license='Apache License 2.0',
    author='cglewis',
    author_email='clewis@iqt.org',
    maintainer='Alice Chang',
    maintainer_email='achang@iqt.org',
    description=(
        'A utility package for extracting and analyzing features in network traffic.'),
    keywords='machine learning network analysis utilities',
    url='https://github.com/CyberReboot/PoseidonML',
)
