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
import threading

PUT_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-put")
READ_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-read")
AG_PATH = os.path.join(testconf.SYNDICATE_AG_ROOT, "syndicate-ag")
AG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/ag/drivers/disk" )

def stop_and_save( output_dir, proc, out_path, save_name ):
    exitcode, out = testlib.stop_gateway( proc, out_path )
    testlib.save_output( output_dir, save_name, out )
    return exitcode, out

class UGThread( threading.Thread ):
    def __init__(self, config_dir, output_dir, output_path, volume_name, **kw ):
        threading.Thread.__init__(self)
        self.read_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", **kw )
        read_gateway_info = testlib.read_gateway( config_dir, self.read_gateway_name )
        self.read_gateway_id = read_gateway_info['g_id']
        
        volume_info = testlib.read_volume( config_dir, volume_name )
        self.volume_id = volume_info['volume_id']
        self.config_dir = config_dir
        self.volume_name = volume_name
        self.output_path = output_path
        self.output_dir = output_dir
        self.exitcode = 0
        self.errormsg = ""
        self.errors = False


    def get_ident(self):
        return self.ident

    def run(self):

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
            (5000, 16000), # 3 blocks, head and tail unaligned
        ]

        self.exitcode = 0

        for (start, end) in ranges:

            if self.errors:
                break

            # only clear reader's cache
            testlib.clear_cache( self.config_dir, volume_id=self.volume_id, gateway_id=self.read_gateway_id )

            for i in xrange(0, 2):

                if self.errors:
                    break

                exitcode, out = testlib.run( READ_PATH, '-d2', '-f', '-c', os.path.join(self.config_dir, 'syndicate.conf'),
                                            '-u', testconf.SYNDICATE_ADMIN, '-v', self.volume_name, '-g', self.read_gateway_name,
                                            self.output_path, start, end - start, valgrind=True )

                out_name = "uncached"
                if i > 0:
                    out_name = "cached"

                testlib.save_output( self.output_dir, 'syndicate-read-thread-%s-%s-%s-%s' % (self.get_ident(), start, end, out_name), out )
                if exitcode != 0:
                    self.exitcode = exitcode
                    self.errormsg = "syndicate-read exit code %s on %s-%s-%s" % (exitcode, start, end, out_name)
                    break

                # correctness 
                if expected_data[start:end] not in out:
                    self.exitcode = -1
                    self.errormsg = "Thread %s missing data for %s-%s-%s" % (self.get_ident(), start, end, out_name)
                    break

            
            if self.exitcode != 0:
                break

        return

    def set_errors(self, e):
        self.errors = e

    def get_exitcode(self):
        return self.exitcode

    def get_errormsg(self):
        return self.errormsg


if __name__ == "__main__":

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )
    num_threads = 8
    threads = []

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
    
    local_path = testlib.make_random_file(16384, dir=testdir)
    output_path = "/%s" % os.path.basename(local_path)
    local_fd = open(local_path, "r")
    expected_data = local_fd.read()
    local_fd.close()

    # start up AG
    AG_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "AG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, AG_gateway_name, "driver=%s" % AG_DRIVER )

    ag_proc, ag_out_path = testlib.start_gateway( config_dir, AG_PATH, testconf.SYNDICATE_ADMIN, volume_name, AG_gateway_name, valgrind=True )
    time.sleep(10)
    if ag_proc.poll() is not None:
        raise Exception("%s exited %s" % (AG_PATH, ag_proc.poll()))

    # create separate threads for UGs 
    for i in xrange(0, num_threads):
        t = UGThread( config_dir, output_dir, output_path, volume_name, caps="ALL", port=(31111 + i + 1), email=testconf.SYNDICATE_ADMIN )
        threads.append(t)

    # run all threads 
    for i in xrange(0, num_threads):
        threads[i].start()

    # wait for them to finish 
    abort = False
    dead = False
    while not abort and not dead:
        for i in xrange(0, num_threads):
            threads[i].join(1.0)
            if threads[i].get_exitcode() != 0:
                abort = True

        if abort:
            for i in xrange(0, num_threads):
                threads[i].set_errors(abort)

            for i in xrange(0, num_threads):
                threads[i].join()

        dead = True
        for i in xrange(0, num_threads):
            if threads[i].isAlive():
                dead = False

    if abort:
        stop_and_save( output_dir, ag_proc, ag_out_path, "syndicate-ag")
        msg = []
        for i in xrange(0, num_threads):
            if threads[i].get_exitcode() != 0:
                msg.append("Thread %s (%s) exited %s, error = '%s'" % (threads[i].get_ident(), i, threads[i].get_exitcode(), threads[i].get_errormsg()))

        raise Exception("\n" + "\n".join(msg))

    ag_exitcode, ag_out = testlib.stop_gateway( ag_proc, ag_out_path )

    testlib.save_output( output_dir, "syndicate-ag", ag_out )

    if ag_exitcode != 0:
        raise Exception("%s exited %s" % (AG_PATH, ag_exitcode))
  
    sys.exit(0)
