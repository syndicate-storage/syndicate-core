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

# creates a multi-block file in an AG and reads various byte-ranges from it.

import os
import sys
import subprocess
import random
import time

import testlib
import testconf 
import shutil
import syndicate
import base64
import json

PUT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-put")
READ_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-read")
LS_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-ls")
AG_PATH = os.path.join(testconf.SYNDICATE_AG_ROOT, "syndicate-ag")
AG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/ag/drivers/disk" )

def stop_and_save( output_dir, proc, out_path, save_name ):
    exitcode, out = testlib.stop_gateway( proc, out_path )
    testlib.save_output( output_dir, save_name, out )
    return exitcode, out

if __name__ == "__main__":

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    # create AG source dataset.  extract config
    ag_driver = syndicate.util.objects.load_driver( AG_DRIVER, None, include_secrets=False )
    assert 'config' in ag_driver
    ag_config_txt = base64.b64decode(ag_driver['config'])
    ag_config = json.loads(ag_config_txt)

    # path to file...
    assert 'DATASET_DIR' in ag_config
    testdir = os.path.join(ag_config['DATASET_DIR'], "dir1/dir2")
    if os.path.exists(ag_config['DATASET_DIR']):
        shutil.rmtree(ag_config['DATASET_DIR'])

    os.makedirs(testdir)
    
    local_path = testlib.make_random_file(16384, dir=testdir)
    output_path = "/dir1/dir2/%s" % os.path.basename(local_path)
    local_fd = open(local_path, "r")
    expected_data = local_fd.read()
    local_fd.close()

    # start up AG
    AG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "AG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, AG_gateway_name, "port=31112", "driver=%s" % AG_DRIVER )

    ag_proc, ag_out_path = testlib.start_gateway( config_dir, AG_PATH, testconf.SYNDICATE_ADMIN, volume_name, AG_gateway_name, valgrind=True )
    time.sleep(30)
    if not testlib.gateway_ping( 31112, 15 ):
        raise Exception("%s exited %s" % (AG_PATH, ag_proc.poll()))

    # should cause the AG to get updated that there's a new gateway 
    read_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    read_gateway_info = testlib.read_gateway( config_dir, read_gateway_name )
    read_gateway_id = read_gateway_info['g_id']

    volume_info = testlib.read_volume( config_dir, volume_name )
    volume_id = volume_info['volume_id']

    # try reading various ranges (these are (start, end) absolute ranges, not offset/length)
    ranges = [
        (1, 200),
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
        (5000, 16000) # 3 blocks, head and tail unaligned
    ]

    for (start, end) in ranges:

        # only clear reader's cache
        testlib.clear_cache( config_dir, volume_id=volume_id, gateway_id=read_gateway_id )

        # do each read twice--once uncached, and one cached 
        for i in xrange(0, 2):
            exitcode, out = testlib.run( READ_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                        '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', read_gateway_name,
                                        output_path, start, end - start, valgrind=True )

            out_name = "uncached"
            if i > 0:
                out_name = "cached"

            testlib.save_output( output_dir, 'syndicate-read-%s-%s-%s' % (start, end, out_name), out )
            if exitcode != 0:
                stop_and_save( output_dir, ag_proc, ag_out_path, "syndicate-ag")
                raise Exception("%s exited %s" % (READ_PATH, exitcode))

            # correctness 
            if expected_data[start:end] not in out:
                stop_and_save( output_dir, ag_proc, ag_out_path, "syndicate-ag")
                raise Exception("Missing data for %s-%s" % (start, end))

    # finally, list it
    for p in ['/', '/dir1', '/dir1/dir2', output_path]:
        exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                     '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', read_gateway_name,
                                     p, valgrind=True )

        testlib.save_output( output_dir, "syndicate-ls-%s" % p.replace("/", "\\x2f" ), out)
        if exitcode != 0:
            stop_and_save(output_dir, ag_proc, ag_out_path, "syndicate-ag")
            raise Exception("Failed to list %s" % p)

    ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )

    testlib.save_output( output_dir, "syndicate-ag", ag_out )

    if ag_exitcode != 0:
        raise Exception("%s exited %s" % (AG_PATH, ag_exitcode))
  
    sys.exit(0)
