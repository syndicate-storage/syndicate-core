#!/usr/bin/env python

"""
   Copyright 2013 The Trustees of Princeton University

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

import os
import sys

source_root = "../"
build_dir = ""
distro = "UNKNOWN"

# is build_root in the args?
i = 0
while i < len(sys.argv):
    if sys.argv[i].startswith('--source-root='):
        source_root = sys.argv[i].split("=", 1)[1]
        sys.argv.remove(sys.argv[i])
        continue

    if sys.argv[i].startswith("--build-dir="):
        build_dir = sys.argv[i].split("=", 1)[1]
        sys.argv.remove(sys.argv[i])
        continue

    if sys.argv[i].startswith("--distro="):
        distro = sys.argv[i].split("=", 1)[1]
        sys.argv.remove(sys.argv[i])
        continue

    i += 1

distro_switch = "-D_DISTRO_%s" % distro

ext_source_root = source_root

ext_modules = [
    Extension("syndicate",
              sources=["syndicate.pyx"],
              libraries=["syndicate"],
              library_dirs=[os.path.join(source_root, build_dir, "../lib")],             # libsyndicate local build
              include_dirs=[os.path.join(source_root, build_dir, "../include")],
              extra_compile_args=["-D__STDC_FORMAT_MACROS", "-D_FORTIFY_SOUCRE", "-D_BUILD_PYTHON", "-fstack-protector", "-fstack-protector-all", distro_switch],
              language="c++"),

    Extension("volume",
              sources=["volume.pyx"],
              libraries=["syndicate", "syndicate-ug"],
              library_dirs=[os.path.join(source_root, build_dir, "../lib")],
              include_dirs=[os.path.join(source_root, build_dir, "../include")],
              extra_compile_args=["-D__STDC_FORMAT_MACROS", "-D_FORTIFY_SOUCRE", "-D_BUILD_PYTHON", "-fstack-protector", "-fstack-protector-all", distro_switch],
              language="c++"),
]


def make_driver_paths(driver_relpath):
    ret = []
    for com in ['config', 'driver', 'secrets']:
        ret.append(os.path.join(ext_source_root, build_dir, driver_relpath + '/' + com))

    return ret


setup(name='syndicate',
      version='0.1',
      description='Syndicate Python library',
      url='https://github.com/syndicate-storage/syndicate-core',
      author='Jude Nelson',
      author_email='syndicate@lists.cs.princeton.edu',
      license='Apache 2.0',
      ext_package='syndicate',
      ext_modules=ext_modules,
      packages=['syndicate',
                'syndicate.ag',
                'syndicate.ag.curation',
                'syndicate.ag.datasets',
                'syndicate.ag.drivers',
                'syndicate.ag.drivers.disk',
                'syndicate.ag.drivers.fs',
                'syndicate.ms',
                'syndicate.observer',
                'syndicate.observer.storage',
                'syndicate.protobufs',
                'syndicate.rg',
                'syndicate.rg.drivers',
                'syndicate.rg.drivers.disk',
                'syndicate.rg.drivers.s3',
                'syndicate.rg.drivers.fs',
                'syndicate.util',
                ],
      package_dir={
                'syndicate.ag': os.path.join(ext_source_root, build_dir, 'syndicate/ag'),
                'syndicate.ag.curation': os.path.join(ext_source_root, build_dir, 'syndicate/ag/curation'),
                'syndicate.ag.datasets': os.path.join(ext_source_root, build_dir, 'syndicate/ag/datasets'),
                'syndicate.ag.drivers': os.path.join(ext_source_root, build_dir, 'syndicate/ag/drivers'),
                'syndicate.ag.drivers.disk': os.path.join(ext_source_root, build_dir, 'syndicate/ag/drivers/disk'),
                'syndicate.ag.drivers.fs': os.path.join(ext_source_root, build_dir, 'syndicate/ag/drivers/fs'),
                'syndicate.ms': os.path.join(ext_source_root, build_dir, 'syndicate/ms'),
                'syndicate.observer': os.path.join(ext_source_root, build_dir, 'syndicate/observer'),
                'syndicate.observer.storage': os.path.join(ext_source_root, build_dir, 'syndicate/observer/storage'),
                'syndicate.protobufs': os.path.join(ext_source_root, build_dir, '../protobufs/python'),
                'syndicate.rg': os.path.join(ext_source_root, build_dir, 'syndicate/rg'),
                'syndicate.rg.drivers': os.path.join(ext_source_root, build_dir, 'syndicate/rg/drivers'),
                'syndicate.rg.drivers.disk': os.path.join(ext_source_root, build_dir, 'syndicate/rg/drivers/disk'),
                'syndicate.rg.drivers.s3': os.path.join(ext_source_root, build_dir, 'syndicate/rg/drivers/s3'),
                'syndicate.rg.drivers.fs': os.path.join(ext_source_root, build_dir, 'syndicate/rg/drivers/fs'),
                'syndicate.util': os.path.join(ext_source_root, build_dir, 'syndicate/util'),
                },
      package_data={
                'syndicate.ag.drivers.disk': make_driver_paths('syndicate/ag/drivers/disk'),
                'syndicate.ag.drivers.fs': make_driver_paths('syndicate/ag/drivers/fs'),
                'syndicate.rg.drivers.disk': make_driver_paths('syndicate/rg/drivers/disk'),
                'syndicate.rg.drivers.s3': make_driver_paths('syndicate/rg/drivers/s3'),
                'syndicate.rg.drivers.fs': make_driver_paths('syndicate/rg/drivers/fs'),
                },
      cmdclass={"build_ext": build_ext},
      )
