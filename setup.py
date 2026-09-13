"""Legacy build metadata for Python 3.6.

Modern Python versions use the PEP 621 metadata in pyproject.toml. Python 3.6
needs a setuptools release older than PEP 621, so the same essentials live here.

The package version has a single source of truth: ``tls_client/__init__.py``
(``__version__``).  Both this file and ``pyproject.toml`` (via ``dynamic =
["version"]`` / ``attr = "tls_client.__version__"``) read it from there, so a
release bump only ever touches one place.
"""

import os
import re

from setuptools import setup
from setuptools.dist import Distribution

_HERE = os.path.abspath(os.path.dirname(__file__))


def _read_version():
    """Return the package version from ``tls_client/__init__.py``.

    Read statically (regex) rather than importing the package, so building does
    not require ``cffi`` or a loadable native library at metadata time.
    """
    path = os.path.join(_HERE, "tls_client", "__init__.py")
    with open(path, "r", encoding="utf-8") as handle:
        source = handle.read()
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.M)
    if match is None:
        raise RuntimeError("unable to find __version__ in %s" % path)
    return match.group(1)


class BinaryDistribution(Distribution):
    def is_pure(self):
        return False


setup(
    distclass=BinaryDistribution,
    name="tls-client-python",
    version=_read_version(),
    description="High-performance CFFI binding for bogdanfinn/tls-client",
    long_description=open(os.path.join(_HERE, "Readme.md"), "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    author="komAAmok",
    packages=["tls_client", "tls_client.fingerprints"],
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
