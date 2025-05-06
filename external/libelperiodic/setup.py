#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from distutils.core import Extension
from os import environ
from sysconfig import get_platform
from os.path import realpath, dirname
from sys import path as sys_path

sys_path.insert(0, realpath(dirname(__file__)))
from build_tools.CheckVersion import CheckVersion

elp_srcs = ['src/periodic.c', 'src/prdic_math.c', \
 'src/prdic_fd.c', \
 'src/prdic_pfd.c', \
 'src/prdic_main_fd.c', 'src/prdic_main_pfd.c', \
 'src/prdic_main.c', \
 'src/prdic_recfilter.c', 'src/prdic_shmtrig.c', \
 'src/prdic_sign.c']

el_args = None if get_platform().startswith('macosx-') else ['-Wl,--version-script=src/Symbol.map',]
module1 = Extension('_elperiodic', sources = elp_srcs, \
    extra_link_args = el_args)

def get_ex_mod():
    if 'NO_PY_EXT' in environ:
        return None
    return [module1]

with open("README.md", "r") as fh:
    long_description = fh.read()

kwargs = {
      'name':'ElPeriodic',
      'version':'1.5',
      'description':'Phase-locked userland scheduling library',
      'long_description': long_description,
      'long_description_content_type': "text/markdown",
      'author':'Maksym Sobolyev',
      'author_email':'sobomax@gmail.com',
      'url':'https://github.com/sobomax/libelperiodic',
      'packages':['elperiodic',],
      'package_dir':{'elperiodic':'python'},
      'ext_modules': get_ex_mod(),
      'python_requires': '>=2.7',
      'cmdclass': {'checkversion': CheckVersion},
      'license': 'BSD-2-Clause',
      'classifiers': [
            'Operating System :: POSIX',
            'Programming Language :: C',
            'Programming Language :: Python'
      ]
}

if __name__ == '__main__':
    setup(**kwargs)
