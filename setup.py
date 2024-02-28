from setuptools import setup, find_packages

setup(
    name='odoh',
    version='3.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'dnsodoh = ObliviousDNS.odoh:main'
        ]
    }
)
