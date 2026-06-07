# setup.py

from setuptools import setup
from setuptools.dist import Distribution

class BinaryDistribution(Distribution):
    def is_pure(foo):
        return False

setup(
    distclass=BinaryDistribution,
)
