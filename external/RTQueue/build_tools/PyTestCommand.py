import sys

from setuptools import Command

class PyTestCommand(Command):
    description = "run tests using pytest"
    user_options = [('pytest-args=', 'a', "Arguments to pass to pytest")]

    def initialize_options(self):
        self.pytest_args = ''

    def finalize_options(self):
        pass

    def run(self):
        import pytest
        errno = pytest.main(self.pytest_args.split())
        sys.exit(errno)
