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
import syndicate
import base64
import json

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

    read_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    read_gateway_info = testlib.read_gateway( config_dir, read_gateway_name )
    read_gateway_id = read_gateway_info['g_id']

    volume_info = testlib.read_volume( config_dir, volume_name )
    volume_id = volume_info['volume_id']

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

    # list files that do not yet exist
    # verify that we can't list them
    descendent_files = ['/dir1', '/dir1/dir2', output_path]
    for i in xrange(0, len(descendent_files)):
        p = descendent_files[i]
        exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                     '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', read_gateway_name,
                                     p, valgrind=True )

        testlib.save_output(output_dir, "syndicate-ls-before-%s" % p.replace("/", "\\x2f" ), out )
        if ("\nFailed to stat '%s': No such file or directory\n" % p) not in out:
            raise Exception("Successfully listed '%s'" % p)

        p_base = p
        if p != '/':
            p_base = os.path.basename(p)

        if ("\nname:     %s\n" % p_base) in out:
            raise Exception("Found '%s' in listing" % p)

        if i + 1 < len(descendent_files):
            if ("name:     %s" % os.path.basename(descendent_files[i+1])) in out:
                raise Exception("Found '%s' in listing" % descendent_files[i+1])

    # start up AG
    AG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "AG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, AG_gateway_name, "port=31112", "driver=%s" % AG_DRIVER )

    ag_proc, ag_out_path = testlib.start_gateway( config_dir, AG_PATH, testconf.SYNDICATE_ADMIN, volume_name, AG_gateway_name, valgrind=True )
    time.sleep(30)

    if not testlib.gateway_ping( 31112, 15 ):
        raise Exception("%s exited %s" % (AG_PATH, ag_proc.poll()))

    # list all files again.  Expect everything to be present.
    descendent_files = ['/', '/dir1', '/dir1/dir2', output_path]
    for i in xrange(0, len(descendent_files)):
        p = descendent_files[i]
        exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                     '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', read_gateway_name,
                                     p, valgrind=True )

        testlib.save_output(output_dir, "syndicate-ls-after-%s" % p.replace("/", "\\x2f" ), out )

        p_base = p
        if p != '/':
            p_base = os.path.basename(p)

        if ("\nname:     %s\n" % p_base) not in out:
            stop_and_save(output_dir, ag_proc, ag_out_path, "syndicate-ag")
            raise Exception("Missing '%s'" % p)

        if i + 1 < len(descendent_files):
            if ("\nname:     %s\n" % os.path.basename(descendent_files[i+1])) not in out:
                stop_and_save(output_dir, ag_proc, ag_out_path, "syndicate-ag")
                raise Exception("Missing child '%s'" % descendent_files[i+1])

    ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )

    testlib.save_output( output_dir, "syndicate-ag", ag_out )

    if ag_exitcode != 0:
        raise Exception("%s exited %s" % (AG_PATH, ag_exitcode))
  
    sys.exit(0)
