#!/usr/bin/env python

from distutils.core import setup

setup(name='l2tester',
      version='1.0',
      author='Datacom',
      url='https://github.com/datacom-teracom/l2tester',
      description='l2tester is a set of tools projected to network traffic tests using the PC interfaces.',
      scripts=['bin/shark', 'bin/sharknado'],
      packages=['l2tester'],
      include_package_data=True,
      platforms='linux',
      install_requires=['scapy', 'pyroute2<0.6.0', 'ipaddress'],
      package_data={'l2tester': ['_l2tester.so']},
      )
