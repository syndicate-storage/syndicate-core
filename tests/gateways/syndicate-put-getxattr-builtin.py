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

PUT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-put")
GETXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-getxattr")
CAT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-cat")
RG_PATH = os.path.join(testconf.SYNDICATE_RG_ROOT, "syndicate-rg")
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )

if __name__ == "__main__":

    local_path = testlib.make_tmp_file(16384, "abcdef\n")
    local_fd = open(local_path, "r")
    local_fd.close()

    block_size = 4096
    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir, blocksize=block_size )

    RG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, RG_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    rg_proc, rg_out_path = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, RG_gateway_name )
    if not testlib.gateway_ping( 31112, 15 ):
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # should cause the RG to get updated that there's a new gateway 
    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    random_part = hex(random.randint(0, 2**32-1))[2:]
    output_path = "/put-%s" % random_part
    exitcode, out = testlib.run( PUT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, local_path, output_path )

    testlib.save_output( output_dir, "syndicate-put", out )

    if exitcode != 0:
        raise Exception("%s exited %s" % (PUT_PATH, exitcode))

    # read the file, to populate the cache 
    exitcode, out = testlib.run( CAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                 '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                 output_path, valgrind=True )

    if exitcode != 0:
        rg_exitcode, rg_out = testlib.stop_gateway( rg_proc, rg_out_path )
        testlib.save_output( output_dir, "syndicate-rg", rg_out )
        raise Exception("Failed to read %s" % path)

    # check cache 
    exitcode, out_get1xattr = testlib.run( GETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"),
                                          '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                          output_path, "user.syndicate_cached_blocks", valgrind=True )

    testlib.save_output( output_dir, 'syndicate-getxattr-cached-blocks', out_get1xattr )
    
    rg_exitcode, rg_out = testlib.stop_gateway( rg_proc, rg_out_path )
    testlib.save_output( output_dir, "syndicate-rg", rg_out )

    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcode))

    if exitcode != 0:
        raise Exception("%s exited %s" % (GETXATTR_PATH, exitcode))
   
    # check for correctnes (all blocks cached)
    cached_blocks = "1" * (16384 / block_size) 
    if 16384 % block_size != 0:
        cached_blocks += "1"

    if '\n' + cached_blocks + '\n' not in out_get1xattr:
        raise Exception("data not found in output")

    sys.exit(0)
