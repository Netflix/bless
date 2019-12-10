import os

from setuptools import setup, find_packages

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

about = {}
with open(os.path.join(ROOT, "bless", "__about__.py")) as f:
    exec(f.read(), about)

setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    description=about["__summary__"],
    license=about["__license__"],
    packages=find_packages(exclude=["test*"]),
    install_requires=[
        'boto3',
        'cryptography',
        'ipaddress',
        'marshmallow',
        'kmsauth'
    ],
    extras_require={
        'tests': [
            'coverage',
            'flake8',
            'pyflakes',
            'pytest',
            'pytest-mock'
        ]
    }
)
