from setuptools import setup

setup(
    name='poseidonml',
    version='0.2.10',
    packages=['poseidonml'],
    package_dir={'poseidonml': 'utils'},
    package_data={'poseidonml': ['models/*']},
    install_requires=open('requirements.txt','r').read().splitlines(),
    license='Apache License 2.0',
    author='cglewis',
    author_email='clewis@iqt.org',
    maintainer='cglewis',
    maintainer_email='clewis@iqt.org',
    description=(
        'A utility package for extracting and analyzing features in network traffic.'),
    keywords='machine learning network analysis utilities',
    url='https://github.com/CyberReboot/PoseidonML',
)
