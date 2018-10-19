#!/usr/bin/env python

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2017, Andrea Fioraldi"
__license__ = "BSD 2-Clause"
__email__ = "andreafioraldi@gmail.com"

from setuptools import setup

VER = "1.0.4"

setup(
    name='angrgdb',
    version=VER,
    license=__license__,
    description='Use angr inside GDB. Create an angr state from the current debugger state. ',
    author=__author__,
    author_email=__email__,
    url='https://github.com/andreafioraldi/angrgdb',
    download_url = 'https://github.com/andreafioraldi/angrgdb/archive/' + VER + '.tar.gz',
    package_dir={'angrgdb': 'angrgdb'},
    packages=['angrgdb'],
    install_requires=['angrdbg'],
)
