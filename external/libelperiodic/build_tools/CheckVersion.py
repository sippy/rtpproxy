import sys
from distutils.core import Command

class CheckVersion(Command):
    description = "Check version number"
    user_options = [
        ('tag=', 't', 'git tag to compare against package version'),
    ]
    extra_compile_args = []
    extra_link_args = []

    def initialize_options(self):
        self.tag = None

    def finalize_options(self):
        if not self.tag:
            raise DistutilsOptionError("You must specify --tag")

    def run(self):
        pkg_version = self.distribution.get_version()
        if self.tag == f'v{pkg_version}':
            return
        sys.stderr.write(f"❌ version {pkg_version} != tag {self.tag}\n")
        sys.exit(1)
