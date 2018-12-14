from setuptools import setup

setup(
    name='poseidonml',
    version='0.2.3',
    packages=['poseidonml'],
    package_dir={'poseidonml': 'utils'},
    package_data={'poseidonml': ['models/*']},
    install_requires=['numpy==1.15.4', 'pika==0.12.0', 'redis==3.0.1',
                      'scikit-learn==0.20.1', 'scipy==1.1.0', 'tensorflow==1.12.0'],
    license='Apache License 2.0',
    author='cglewis',
    author_email='clewis@iqt.org',
    maintainer='Charlie Lewis',
    maintainer_email='clewis@iqt.org',
    description=(
        'A utility package for extracting and analyzing features in network traffic.'),
    keywords='machine learning network analysis utilities',
    url='https://github.com/CyberReboot/PoseidonML',
)
