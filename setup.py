from sys import exit, path as sys_path
from setuptools import setup, Extension
from os.path import realpath, dirname, join as path_join
from sys import argv as sys_argv
import sys

sys_path.insert(0, realpath(dirname(__file__)))
try:
    from build_tools.PyTestCommand import PyTestCommand
except Exception:
    PyTestCommand = None

mod_name = 'LossyQueue'
mod_name_dbg = mod_name + '_debug'

mod_dir = dirname(realpath(__file__))
src_dir = 'src'

include_dirs = [path_join(mod_dir, src_dir)]

compile_args = []
link_args = []
if sys.platform.startswith('linux'):
    compile_args = ['-flto']
    version_script = path_join(mod_dir, 'python', 'symbols.map')
    link_args = ['-flto', f'-Wl,--version-script={version_script}']
    debug_cflags = ['-g3', '-O0', '-DDEBUG_MOD']
elif sys.platform == 'darwin':
    debug_cflags = ['-g', '-O0', '-DDEBUG_MOD']
elif sys.platform == 'win32':
    compile_args = ['/std:c11', '/experimental:c11atomics', '/D_CRT_USE_C11_ATOMICS']
    debug_cflags = ['/Zi', '/Od', '/DDEBUG_MOD']
else:
    debug_cflags = ['-g', '-O0', '-DDEBUG_MOD']

mod_common_args = {
    'sources': ['python/LossyQueue_mod.c', path_join(src_dir, 'SPMCQueue.c')],
    'include_dirs': include_dirs,
    'extra_compile_args': compile_args,
    'extra_link_args': link_args
}
mod_debug_args = mod_common_args.copy()
mod_debug_args['extra_compile_args'] = mod_debug_args['extra_compile_args'] + debug_cflags

module1 = Extension(mod_name, **mod_common_args)
module2 = Extension(mod_name_dbg, **mod_debug_args)

with open("README.md", "r") as fh:
    long_description = fh.read()

setup (name = 'RTQueue',
       version = '1.0',
       description = 'This is a package for LossyQueue module',
       ext_modules = [module1, module2],
       cmdclass={'test': PyTestCommand} if PyTestCommand else {},
       long_description=long_description,
       long_description_content_type='text/markdown',
)
