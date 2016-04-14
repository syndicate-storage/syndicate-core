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
RG_PATH = os.path.join(testconf.SYNDICATE_RG_ROOT, "syndicate-rg")
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )

if __name__ == "__main__":
    usage = "%s LOCAL_FILE COUNT" % sys.argv[0]

    if len(sys.argv) <= 1:
        print >> sys.stderr, usage
        sys.exit(1)

    local_path = sys.argv[1]
    if not os.path.exists(local_path) or not os.path.isfile(local_path):
        print >> sys.stderr, usage
        sys.exit(1)

    try:
        count = int(sys.argv[2])
    except:
        print >> sys.stderr, usage
        sys.exit(1)

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    RG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, RG_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    rg_proc = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, RG_gateway_name )
    time.sleep(1)
    if rg_proc.poll() is not None:
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # should cause the RG to get updated that there's a new gateway 
    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )

    random_part = hex(random.randint(0, 2**32-1))[2:]
    paths = []
    for i in xrange(0, count):
        paths.append( local_path )
        paths.append( "/put-%s-%s" % (random_part, i) )

    exitcode, out = testlib.run( PUT_PATH, '-B', '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'), '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name, *paths )
    rg_exitcode, rg_out = testlib.stop_gateway( rg_proc )

    testlib.save_output( output_dir, "syndicate-put", out )
    testlib.save_output( output_dir, "syndicate-rg", rg_out )

    if exitcode != 0:
        raise Exception("%s exited %s" % (PUT_PATH, exitcode))

    if rg_exitcode != 0:
        raise Exception("%s exited %s" % (RG_PATH, rg_exitcode))
   
    benchmark_data = testlib.get_benchmark_data( out )
    if benchmark_data is None:
        raise Exception("No benchmark data")

    print ""
    print ",".join([str(bd) for bd in benchmark_data])
    sys.exit(0)
