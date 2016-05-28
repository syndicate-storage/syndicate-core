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

TOUCH_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-touch")
STAT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-stat")
LS_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-ls")
UNLINK_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-unlink")
RG_PATH = os.path.join(testconf.SYNDICATE_RG_ROOT, "syndicate-rg")
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )

NUM_FILES = 10

def stop_and_save( output_dir, proc, out_path, save_name ):
    exitcode, out = testlib.stop_gateway( proc, out_path )
    testlib.save_output( output_dir, save_name, out )
    return exitcode, out


if __name__ == "__main__":

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    RG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, RG_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    rg_proc, rg_out_path = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, RG_gateway_name )
    time.sleep(1)
    if rg_proc.poll() is not None:
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # should cause the RG to get updated that there's a new gateway 
    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    # touch $NUM_FILES files 
    random_part = hex(random.randint(0, 2**32-1))[2:]
    expected_paths = []

    for i in xrange(0, NUM_FILES):
        output_path = "/touch-%s-%s" % (random_part, i)
        expected_paths.append(output_path)

        exitcode, out = testlib.run( TOUCH_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, output_path )
        testlib.save_output( output_dir, "syndicate-touch-%s" % i, out )
        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (TOUCH_PATH, exitcode))

    # list them 
    exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, '/' )
    testlib.save_output( output_dir, "syndicate-ls", out )
    if exitcode != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (LS_PATH, exitcode))

    # verify that they're all there 
    for path in expected_paths:
        if path.strip("/") not in out:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("Not found in listing: %s" % path)

    # delete them all 
    for path in expected_paths:
        exitcode, out = testlib.run( UNLINK_PATH, "-d2", '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, path)
        testlib.save_output( output_dir, "syndicate-unlink-%s" % i, out )
        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (UNLINK_PATH, exitcode))

    # list them; should be nothing 
    exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, '/' )
    testlib.save_output( output_dir, "syndicate-ls", out )
    if exitcode != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (LS_PATH, exitcode))

    # verify that none are there
    for path in expected_paths:
        if path.strip("/") in out:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("Still present in listing: %s" % path)

    # stop RG 
    rg_exitcode, rg_out = stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcod))
            
    sys.exit(0)
