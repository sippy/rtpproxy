from sys import exit, path as sys_path
from distutils.core import setup, Extension
from os.path import realpath, dirname, join as path_join
from sys import argv as sys_argv

sys_path.insert(0, realpath(dirname(__file__)))
from build_tools.PyTestCommand import PyTestCommand

mod_name = 'LossyQueue'
mod_name_dbg = mod_name + '_debug'

mod_dir = dirname(realpath(__file__))
src_dir = 'src/'

compile_args = [f'-I{src_dir}', '-flto']
link_args = ['-flto', '-Wl,--version-script=python/symbols.map']
debug_cflags = ['-g3', '-O0', '-DDEBUG_MOD']
mod_common_args = {
    'sources': ['python/LossyQueue_mod.c', src_dir + 'SPMCQueue.c'],
    'extra_compile_args': compile_args,
    'extra_link_args': link_args
}
mod_debug_args = mod_common_args.copy()
mod_debug_args['extra_compile_args'] = mod_debug_args['extra_compile_args'] + debug_cflags

module1 = Extension(mod_name, **mod_common_args)
module2 = Extension(mod_name_dbg, **mod_debug_args)

setup (name = 'SPMCQueue',
       version = '1.0',
       description = 'This is a package for LossyQueue module',
       ext_modules = [module1, module2],
       cmdclass={'test': PyTestCommand},
)

