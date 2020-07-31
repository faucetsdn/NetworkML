# WARNING about imp deprecation because of setuptools
from setuptools import setup, find_packages

setup(
    name='networkml',
    version=open('VERSION', 'r').read().strip(),
    include_package_data=True,
    packages=find_packages(),
    install_requires=open('requirements.txt', 'r').read().splitlines(),
    scripts=['bin/networkml'],
    license='Apache License 2.0',
    author='cglewis',
    author_email='clewis@iqt.org',
    maintainer='cglewis',
    maintainer_email='clewis@iqt.org',
    description=(
        'A utility package for extracting and analyzing features in network traffic.'),
    keywords='machine learning network analysis utilities',
    url='https://github.com/IQTLabs/NetworkML',
)
