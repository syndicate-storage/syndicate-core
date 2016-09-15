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

REPL_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-repl")
MKDIR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-mkdir")
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
    if not testlib.gateway_ping(31112, 15):
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

    # make target directory
    exitcode, out = testlib.run( MKDIR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, "/newdir", valgrind=True )
    testlib.save_output( output_dir, "syndicate-mkdir", out )

    if exitcode != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (PUT_PATH, exitcode))

    # generate the commands to feed into the REPL
    repl_cmd = ""
    for i in xrange(0, NUM_FILES):
        output_path = "/put-%s-%s" % (random_part, i)
        output_paths.append(output_path)

        repl_cmd += "create /put-%s-%s 0644\n" % (random_part, i)
        repl_cmd += "write 0 0 %s %s\n" % (len(expected_data), expected_data)
        repl_cmd += "close 0\n"

    for i in xrange(0, NUM_FILES):
        input_path = output_paths[i]
        output_path_samedir = output_paths[i] + "-renamed"
        output_path_newdir = "/newdir/" + output_paths[i] + "-renamed"
        output_path = None

        # alternate between renaming into the same directory versus a new directory
        if i % 2 == 0:
            output_path = output_path_samedir
        else:
            output_path = output_path_newdir

        repl_cmd += "rename %s %s\n" % (input_path, output_path)
       
    for i in xrange(0, NUM_FILES):
        output_path_samedir = output_paths[i] + "-renamed"
        output_path_newdir = "/newdir/" + output_paths[i] + "-renamed"
        path = None
        
        # select the correct path to read, based on the above generation
        if i % 2 == 0:
            path = output_path_samedir
        else:
            path = output_path_newdir

        # clear cache
        read_cache_dir = testlib.cache_dir( config_dir, volume_id, cat_gateway_id )
        rg_cache_dir = testlib.cache_dir( config_dir, volume_id, rg_gateway_id )

        repl_cmd += "shell rm -rf %s\n" % read_cache_dir
        repl_cmd += "shell rm -rf %s\n" % rg_cache_dir

        # open and read in full
        repl_cmd += "open %s 2\n" % path
        repl_cmd += "read 0 0 %s\n" % len(expected_data)
        repl_cmd += "close 0\n"

    
    print "\n".join( ["< %s" % l[:min(80, len(l))] + "..."[:min(max(0, len(l)-80), 3)] for l in repl_cmd.split("\n")] )

    # open the syndicate REPL
    ug_proc, ug_out_path = testlib.start_gateway( config_dir, REPL_PATH, testconf.SYNDICATE_ADMIN, volume_name, gateway_name, valgrind=True, stdin=True)
    if not testlib.gateway_ping( 31111, 15 ):
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (REPL_PATH, repl_proc.poll()))

    out, exit_rc = testlib.finish( ug_proc, stdin=repl_cmd, out_path=ug_out_path, valgrind=True )
    testlib.save_output( output_dir, "syndicate-repl", out )

    if exit_rc != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (REPL_PATH, exit_rc))

    rg_exitcode, rg_out = stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcode))

    # search for the expected data
    # should show up in the read commands
    off = 0
    for i in xrange(0, NUM_FILES):
        off = out[off:].find(expected_data)
        if off < 0:
            # not found!
            raise Exception("Missing count %s of expected data" % i)

        off += len(expected_data)

    # TODO: search RG output for renames
    sys.exit(0)
