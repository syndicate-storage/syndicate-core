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
import base64
import json

import testlib
import testconf 
import shutil

import syndicate

CAT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-cat")
LS_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-ls")
REFRESH_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-refresh")
AG_PATH = os.path.join(testconf.SYNDICATE_AG_ROOT, "syndicate-ag")
AG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/ag/drivers/disk" )

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
    testdir = ag_config['DATASET_DIR']
    if os.path.exists(testdir):
        shutil.rmtree(testdir)

    inner_dir = os.path.join(testdir, "to_remove")
    os.makedirs(inner_dir)

    # put a file to publish
    local_paths = []
    for i in xrange(0, 1):
        local_path = testlib.make_random_file(16384, dir=inner_dir)
        local_paths.append(local_path)

    # start AG
    AG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "AG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, AG_gateway_name, "port=31112", "driver=%s" % AG_DRIVER )
    ag_proc, ag_out_path = testlib.start_gateway( config_dir, AG_PATH, testconf.SYNDICATE_ADMIN, volume_name, AG_gateway_name, valgrind=True )
    time.sleep(20)

    if ag_proc.poll() is not None:
        ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
        testlib.save_output(output_dir, "syndicate-ag", ag_out)
        raise Exception("%s exited %s" % (AG_PATH, ag_proc.poll()))

    # should cause the AG to get updated that there's a new gateway 
    ug_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    # remove inner dir, and have the AG refresh
    shutil.rmtree(inner_dir)
    exitcode, out = testlib.run( REFRESH_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', ug_gateway_name, '/to_remove', valgrind=True )
    testlib.save_output( output_dir, "syndicate-refresh", out )

    if exitcode != 0:
        ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
        testlib.save_output(output_dir, "syndicate-ag", ag_out)
        raise Exception("syndicate-refresh exit code %s" % exitcode) 

    if "Failed to refresh" in out:
        ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
        testlib.save_output(output_dir, "syndicate-ag", ag_out)
        raise Exception("syndicate-refresh failed")

    # wait for AG to sync
    time.sleep(10)

    expected_data_error = False
    for i in xrange(0,len(local_paths)):
        local_path = local_paths[i]
        output_path = "/" + os.path.basename(local_path)
        exitcode, out = testlib.run( CAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', ug_gateway_name, output_path, valgrind=True )

        testlib.save_output( output_dir, 'syndicate-cat-%s' % i, out )

        if exitcode == 0:
            ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
            testlib.save_output(output_dir, "syndicate-ag", ag_out)
            raise Exception("%s succeeded when it should not have" % (CAT_PATH, exitcode))

    # ls should indicate no files 
    exitcode, out = testlib.run( LS_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', ug_gateway_name, "/", valgrind=True )
    testlib.save_output( output_dir, 'syndicate-ls', out )

    for local_path in local_paths + ['/to_remove']:
        search_str = "name:     %s" % os.path.basename(local_path)
        if search_str in out:
            ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
            testlib.save_output(output_dir, "syndicate-ag", ag_out)
            raise Exception("Still listing path '%s'" % local_path)

    ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
    testlib.save_output(output_dir, "syndicate-ag", ag_out)

    if ag_exitcode != 0:
        raise Exception("%s exited %s" % (AG_PATH, ag_exitcode))
   
    # check for correctnes 
    if expected_data_error:
        raise Exception("data not found in output")

    sys.exit(0)
