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
READ_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-read")
RG_PATH = os.path.join(testconf.SYNDICATE_RG_ROOT, "syndicate-rg")
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )

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
    volume_name = testlib.add_test_volume( config_dir )

    RG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, RG_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    rg_proc, rg_out_path = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, RG_gateway_name )
    if not testlib.gateway_ping( 31112, 15 ):
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # should cause the RG to get updated that there's a new gateway 
    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    read_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    random_part = hex(random.randint(0, 2**32-1))[2:]
    output_path = "/put-%s" % random_part
    exitcode, out = testlib.run( PUT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, local_path, output_path )

    testlib.save_output( output_dir, "syndicate-put", out )

    if exitcode != 0:
        raise Exception("%s exited %s" % (PUT_PATH, exitcode))

    # try reading various ranges (these are (start, end) absolute ranges, not offset/length)
    ranges = [
        (0, 4096),  # 1 block, aligned
        (0, 8192),  # 2 blocks, aligned
        (0, 1000),  # 1 block, tail unaligned
        (0, 6000),  # 2 blocks, tail unaligned
        (100, 4000), # 1 block, head unaligned
        (5000, 10000), # 2 blocks, head and tail unaligned
        (4096, 10000), # 2 blocks, tail unaligned
        (5000, 8192),  # 2 blocks, head unalighed
        (4096, 16834), # 3 blocks, aligned
        (5000, 16384), # 3 blocks, head unaligned
        (4096, 16000), # 3 blocks, tail unaligned
        (5000, 16000), # 3 blocks, head and tail unaligned
    ]

    for (start, end) in ranges:

        testlib.clear_cache( config_dir )
        exitcode, out = testlib.run( READ_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                    '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', read_gateway_name,
                                    output_path, start, end - start, valgrind=True )
        testlib.save_output( output_dir, 'syndicate-read-%s-%s' % (start, end), out )
        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("%s exited %s" % (READ_PATH, exitcode))

        # correctness 
        if expected_data[start:end] not in out:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            raise Exception("Missing data for %s-%s" % (start, end))

    rg_exitcode, rg_out = testlib.stop_gateway( rg_proc, rg_out_path )

    testlib.save_output( output_dir, "syndicate-rg", rg_out )

    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcode))
  
    sys.exit(0)
