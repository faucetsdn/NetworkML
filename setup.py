from setuptools import setup

setup(
    name='networkml',
    version=open('VERSION', 'r').read().strip(),
    packages=['networkml', 'networkml.algorithms', 'networkml.algorithms.sos',
              'networkml.parsers', 'networkml.parsers.netflow',
              'networkml.parsers.pcap', 'networkml.utils'],
    package_data={'networkml': ['trained_models/*', 'configs/*']},
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
    url='https://github.com/CyberReboot/NetworkML',
)
