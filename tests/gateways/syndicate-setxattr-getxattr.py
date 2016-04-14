#!/usr/bin/env python

"""
   Copyright 2016 The Trustees of Princeton University

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

import os
import sys
import subprocess
import random
import time

import testlib
import testconf 
import shutil

TOUCH_PATH = os.path.join( testconf.SYNDICATE_UG_ROOT, "syndicate-touch" )
SETXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-setxattr")
GETXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-getxattr")

if __name__ == "__main__":
    random_part = hex(random.randint(0, 2**32-1))[2:]

    path = '/setxattr-%s' % random_part
    attr_name_base = 'foo-%s' % random_part
    attr_value_base = 'bar-%s' % random_part

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    random_part = hex(random.randint(0, 2**32-1))[2:]
   
    exitcode, out = testlib.run( TOUCH_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                path )

    testlib.save_output( output_dir, "syndicate-touch", out )

    if exitcode != 0:
        raise Exception("Failed to touch %s" % path)

    # do setxattr a few times
    # 1 attr
    exitcode, out_1attr = testlib.run( SETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                      '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,  
                                      path, attr_name_base + "-1attr", attr_value_base + "-1attr", valgrind=True )

    testlib.save_output( output_dir, "syndicate-setxattr-1attr", out_1attr )
    if exitcode != 0:
        raise Exception("%s exited %s" % (SETXATTR_PATH, exitcode))

    # 5 attrs at once
    exitcode, out_5attr = testlib.run( SETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                      '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,  
                                       path,
                                       attr_name_base + "-5attr-1", attr_value_base + "-5attr-1",
                                       attr_name_base + "-5attr-2", attr_value_base + "-5attr-2",
                                       attr_name_base + "-5attr-3", attr_value_base + "-5attr-3",
                                       attr_name_base + "-5attr-4", attr_value_base + "-5attr-4",
                                       attr_name_base + "-5attr-5", attr_value_base + "-5attr-5",
                                       valgrind=True )

    testlib.save_output( output_dir, "syndicate-setxattr-5attr", out_5attr )
    if exitcode != 0:
        raise Exception("%s exited %s" % (SETXATTR_PATH, exitcode))

    # get 1 xattr 
    exitcode, out_get1xattr = testlib.run( GETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"),
                                          '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                          path, attr_name_base + '-1attr', valgrind=True )

    testlib.save_output( output_dir, 'syndicate-getxattr-1attr', out_get1xattr )
    if exitcode != 0:
        raise Exception("%s exited %s" % (LISTXATTR_PATH, exitcode))

    # did we get it?
    if attr_value_base + '-1attr' not in out_get1xattr:
        raise Exception("Missing expected attribute value for '%s'" % (attr_name_base + '-1attr'))

    # get 5 attrs at once 
    exitcode, out_get5xattr = testlib.run( GETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                          '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                          path,
                                          attr_name_base + '-5attr-1',
                                          attr_name_base + '-5attr-2',
                                          attr_name_base + '-5attr-3',
                                          attr_name_base + '-5attr-4',
                                          attr_name_base + '-5attr-5',
                                          valgrind=True )

    testlib.save_output( output_dir, "syndicate-getxattr-5attr", out_get5xattr )
    if exitcode != 0:
        raise Exception("%s exited %s" % (GETXATTR_PATH, exitcode))

    # did we get them?
    for i in xrange(1, 6):
        xattr_value = attr_value_base + "-5attr-%s" % i
        if xattr_value not in out_get5xattr:
            raise Exception("Missing expected attribute values for %s", xattr_value)

    sys.exit(0)
