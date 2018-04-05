#!/usr/bin/env python

from distutils.core import setup

setup(name = 'l2tester',
	version = '1.0',
	author = 'Datacom',
	url = 'https://github.com/datacom-teracom/l2tester',
	scripts = ['bin/shark', 'bin/sharknado'],
	packages = ['l2tester'],
	package_data = { 'l2tester' : ['_l2tester.so'] },
	)
