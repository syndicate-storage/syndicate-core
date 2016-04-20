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
COORD_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-coord" )
REMOVEXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-removexattr")
LISTXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-listxattr")

if __name__ == "__main__":
    random_part = hex(random.randint(0, 2**32-1))[2:]

    path = '/setxattr-%s' % random_part
    attr_name_base = 'foo-%s' % random_part
    attr_value_base = 'bar-%s' % random_part

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    gateway_client_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL",  email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, gateway_client_name, "port=31112" )

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

    # start up xattr coordinator,
    coord_proc, coord_out_path = testlib.start_gateway( config_dir, COORD_PATH, testconf.SYNDICATE_ADMIN, volume_name, gateway_name, path, valgrind=True )
    time.sleep(1)
    if coord_proc.poll() is not None:
        raise Exception("%s exited %s" % (COORD_PATH, coord_proc.poll()))

    # remove 1 xattr, from the client
    exitcode, out_remove1xattr = testlib.run( REMOVEXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"),
                                          '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_client_name,
                                          path, attr_name_base + '-1attr', valgrind=True )

    testlib.save_output( output_dir, 'syndicate-removexattr-1attr', out_remove1xattr )
    if exitcode != 0:
        coord_exitcode, coord_out = testlib.stop_gateway( coord_proc, coord_out_path )
        testlib.save_output( output_dir, "syndicate-coord-xattr", coord_out )
        raise Exception("%s exited %s" % (REMOVEXATTR_PATH, exitcode))

    # remove 5 attrs at once, from the client
    exitcode, out_remove5xattr = testlib.run( REMOVEXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                          '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_client_name,
                                          path,
                                          attr_name_base + '-5attr-1',
                                          attr_name_base + '-5attr-2',
                                          attr_name_base + '-5attr-3',
                                          attr_name_base + '-5attr-4',
                                          attr_name_base + '-5attr-5',
                                          valgrind=True )

    testlib.save_output( output_dir, "syndicate-removexattr-5attr", out_remove5xattr )

    if exitcode != 0:
        coord_exitcode, coord_out = testlib.stop_gateway( coord_proc, coord_out_path )
        testlib.save_output( output_dir, "syndicate-coord-xattr", coord_out )
        raise Exception("%s exited %s" % (REMOVEXATTR_PATH, exitcode))

    # make sure we have none 
    exitcode, listxattr_out = testlib.run( LISTXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                           '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_client_name,
                                           path, valgrind=True )

    coord_exitcode, coord_out = testlib.stop_gateway( coord_proc, coord_out_path )
    testlib.save_output( output_dir, "syndicate-coord-xattr", coord_out )
    if coord_exitcode != 0:
        raise Exception("%s exited %s" % (COORD_PATH, exitcode))

    testlib.save_output( output_dir, 'syndicate_listxattr', listxattr_out )
    if exitcode != 0:
        raise Exception("%s exited %s" % (LISTXATTR_PATH, exitcode))

    # none of the attrs should be there 
    for attr in [attr_name_base + '-1attr'] + [attr_name_base + ('-5attr-%s' % i) for i in xrange(1,6)]:
        if attr in listxattr_out:
            raise Exception("Still have '%s'" % attr)

    sys.exit(0)
