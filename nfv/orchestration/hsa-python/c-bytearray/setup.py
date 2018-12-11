from distutils.core import setup, Extension
import sys

if sys.version_info < (2,7):
	module = Extension('c_wildcard',
		sources = ['util.c','array.c','py_wildcard.c'],
		extra_compile_args = ['-std=gnu99','-lm'],
		define_macros = [('PYTHON2_6',None)],
		include_dirs = ['.'])
else:
        module = Extension('c_wildcard',
                sources = ['util.c','array.c','py_wildcard.c'],
                extra_compile_args = ['-std=gnu99','-lm'],
                define_macros = [],
                include_dirs = ['.'])

setup(	name = 'c_wildcard', 
	version = '1.0', 
	description = 'A Python-like bytearray implementation and utility functions',
	author = 'Peyman Kazemian',
	author_email = 'peyman.kazemian@gmail.com',
	ext_modules = [module],
)
