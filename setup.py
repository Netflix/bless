import os

from setuptools import setup

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

about = {}
with open(os.path.join(ROOT, "bless", "__about__.py")) as f:
    exec (f.read(), about)

setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    description=about["__summary__"],
    license=about["__license__"],
    packages=[],
    install_requires=[
        'boto3==1.3.1',
        'botocore==1.4.37',
        'cffi==1.7.0',
        'cryptography==1.4',
        'docutils==0.12',
        'enum34==1.1.6',
        'futures==3.0.5',
        'idna==2.1',
        'ipaddress==1.0.16',
        'jmespath==0.9.0',
        'marshmallow==2.9.0',
        'pyasn1==0.1.9',
        'pycparser==2.14',
        'python-dateutil==2.5.3',
        'six==1.10.0'
    ],
    extras_require={
        'tests': [
            'coverage==4.1',
            'flake8==2.6.2',
            'mccabe==0.5.0',
            'pep8==1.7.0',
            'py==1.4.31',
            'pyflakes==1.2.3',
            'pytest==2.9.2'
        ]
    }
)
