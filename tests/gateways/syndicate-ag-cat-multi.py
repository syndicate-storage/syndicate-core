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

    os.makedirs(testdir)

    # put a file to publish
    local_paths = []
    expected_datas = []
    output_paths = []
    for i in xrange(0, 3):
        local_path = testlib.make_random_file(16384, dir=testdir)
        local_fd = open(local_path, "r")
        expected_data = local_fd.read()
        local_fd.close()

        local_paths.append(local_path)
        expected_datas.append(expected_data)
        output_paths.append( "/" + os.path.basename(local_path))

    # start AG
    AG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "AG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, AG_gateway_name, "port=31112", "driver=%s" % AG_DRIVER )
    ag_proc, ag_out_path = testlib.start_gateway( config_dir, AG_PATH, testconf.SYNDICATE_ADMIN, volume_name, AG_gateway_name, valgrind=True )
    time.sleep(30)

    if not testlib.gateway_ping( 31112, 15 ):
        ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
        testlib.save_output(output_dir, "syndicate-ag", ag_out)
        raise Exception("%s exited %s" % (AG_PATH, ag_proc.poll()))

    # should cause the AG to get updated that there's a new gateway 
    cat_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    exitcode, out = testlib.run( CAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', cat_gateway_name, *output_paths, valgrind=True )
    testlib.save_output(output_dir, "syndicate-cat", out )

    if exitcode != 0:
        ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
        testlib.save_output(output_dir, "syndicate-ag", ag_out)
        raise Exception("%s exited %s" % (CAT_PATH, exitcode))

    # should get all data 
    for i in xrange(0, len(expected_datas)):
        ed = expected_datas[i]
        if ed not in out:
            ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
            testlib.save_output(output_dir, "syndicate-ag", ag_out)
            raise Exception("Missing expected data for %s" % output_paths[i])

    ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )
    testlib.save_output(output_dir, "syndicate-ag", ag_out)

    if ag_exitcode != 0:
        raise Exception("%s exited %s" % (AG_PATH, ag_exitcode))
   
    sys.exit(0)
