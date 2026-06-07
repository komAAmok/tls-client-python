# setup.py


from setuptools import setup
from setuptools.dist import Distribution

class BinaryDistribution(Distribution):
    def has_ext_modules(foo):
        return True

    def is_pure(foo):
        return False

# 仅传递 distclass，其他所有配置都会自动从 pyproject.toml 中读取并合并
setup(
    distclass=BinaryDistribution,
)
