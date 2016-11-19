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
CAT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-cat")
MKDIR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-mkdir")
RENAME_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-rename")
RG_PATH = os.path.join(testconf.SYNDICATE_RG_ROOT, "syndicate-rg")
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )
NUM_FILES = 2

def stop_and_save( output_dir, proc, out_path, save_name ):
    exitcode, out = testlib.stop_gateway( proc, out_path )
    testlib.save_output( output_dir, save_name, out )
    return exitcode, out

if __name__ == "__main__":

    local_path = testlib.make_random_file(16384)
    local_fd = open(local_path, "r")
    expected_data = local_fd.read()
    local_fd.close()

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir, blocksize=1024 )

    RG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, RG_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    rg_proc, rg_out_path = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, RG_gateway_name, valgrind=True )
    if not testlib.gateway_ping( 31112, 15 ):
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # should cause the RG to get updated that there's a new gateway 
    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    cat_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    # look up reader gateway
    cat_gateway_info = testlib.read_gateway( config_dir, cat_gateway_name )
    cat_gateway_id = cat_gateway_info['g_id']

    # look up RG 
    rg_gateway_info = testlib.read_gateway( config_dir, RG_gateway_name )
    rg_gateway_id = rg_gateway_info['g_id']

    volume_info = testlib.read_volume( config_dir, volume_name )
    volume_id = volume_info['volume_id']

    random_part = hex(random.randint(0, 2**32-1))[2:]
    output_paths = []

    # make NUM_FILES files
    for i in xrange(0, NUM_FILES):
        output_path = "/put-%s-%s" % (random_part, i)
        output_paths.append(output_path)

        exitcode, out = testlib.run( PUT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, local_path, output_path, valgrind=True )
        testlib.save_output( output_dir, "syndicate-put-%s" % i, out )

        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (PUT_PATH, exitcode))

    # rename file i to overwrite file i+1
    for i in xrange(0, NUM_FILES, 2):
        input_path = output_paths[i]
        output_path = output_paths[i+1]
        
        # rename into the same directory or into the new directory
        exitcode, out = testlib.run( RENAME_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, input_path, output_path, valgrind=True )
        testlib.save_output( output_dir, "syndicate-rename-%s" % i, out )

        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (RENAME_PATH, exitcode) )

    for i in xrange(0, NUM_FILES, 2):
        path = output_paths[i+1]

        # clear the cache first, to make sure we fetch the new manifest from the RG
        testlib.clear_cache( config_dir, gateway_id=cat_gateway_id, volume_id=volume_id )
        testlib.clear_cache( config_dir, gateway_id=rg_gateway_id, volume_id=volume_id )

        exitcode, out = testlib.run( CAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', cat_gateway_name, path, valgrind=True )
        testlib.save_output( output_dir, 'syndicate-cat-%s' % i, out )
        
        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (CAT_PATH, exitcode)) 

        # check for correctnes 
        if expected_data not in out:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("data not found in output")

    rg_exitcode, rg_out = stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcode))

    # TODO: search RG output for renames
    sys.exit(0)
