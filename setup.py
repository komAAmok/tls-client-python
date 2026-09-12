"""Legacy build metadata for Python 3.6.

Modern Python versions use the PEP 621 metadata in pyproject.toml. Python 3.6
needs a setuptools release older than PEP 621, so the same essentials live here.
"""

from setuptools import setup
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    def is_pure(self):
        return False


setup(
    distclass=BinaryDistribution,
    name="tls-client-python",
    version="1.16.0.1",
    description="High-performance CFFI binding for bogdanfinn/tls-client",
    long_description=open("Readme.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    author="komAAmok",
    packages=["tls_client"],
    package_data={"tls_client": ["bin/*.so", "bin/*.dylib", "bin/*.dll", "py.typed"]},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.6,<3.15",
    install_requires=[
        "cffi>=1.14.0",
        "typing_extensions>=4.1,<4.2; python_version<'3.7'",
        "typing_extensions>=4.1; python_version>='3.7' and python_version<'3.10'",
    ],
)
