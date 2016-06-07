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

PUT_PATH = os.path.join( testconf.SYNDICATE_UG_ROOT, "syndicate-put" )
STAT_PATH = os.path.join( testconf.SYNDICATE_UG_ROOT, "syndicate-stat" )
SETXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-setxattr")
GETXATTR_PATH = os.path.join(testconf.SYNDICATE_UG_ROOT, "syndicate-getxattr")
COORD_PATH = os.path.join( testconf.SYNDICATE_UG_ROOT, "syndicate-coord" )
CAT_PATH = os.path.join( testconf.SYNDICATE_UG_ROOT, "syndicate-cat" )
RG_PATH = os.path.join( testconf.SYNDICATE_RG_ROOT, "syndicate-rg" )
RG_DRIVER = os.path.join(testconf.SYNDICATE_PYTHON_ROOT, "syndicate/rg/drivers/disk" )

def stop_and_save( output_dir, proc, out_path, save_name ):
    exitcode, out = testlib.stop_gateway( proc, out_path )
    testlib.save_output( output_dir, save_name, out )
    return exitcode, out

if __name__ == "__main__":
    random_part = hex(random.randint(0, 2**32-1))[2:]
    random_file_path = testlib.make_random_file( 16384 )

    path = '/setxattr-%s' % random_part

    # test built-in attrs
    builtin_xattrs = [
        "user.syndicate_coordinator",
        "user.syndicate_cached_blocks",
        "user.syndicate_cached_file_path",
        "user.syndicate_read_ttl",
        "user.syndicate_write_ttl"
    ]
    builtin_xattr_expected_values = {
        "user.syndicate_coordinator": None,
        "user.syndicate_cached_blocks": "0000", # for the getxattr gateway
        "user.syndicate_cached_file_path": None,
        "user.syndicate_read_ttl": "5000",
        "user.syndicate_write_ttl": "0"
    }

    # other attrs
    attr_name_base = 'foo-%s' % random_part
    attr_value_base = 'bar-%s' % random_part

    config_dir, output_dir = testlib.test_setup()
    volume_name = testlib.add_test_volume( config_dir )

    gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", email=testconf.SYNDICATE_ADMIN )
    getxattr_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "UG", caps="ALL", port=31113, email=testconf.SYNDICATE_ADMIN )

    rg_gateway_name = testlib.add_test_gateway( config_dir, volume_name, "RG", caps="NONE", email=testconf.SYNDICATE_ADMIN )
    testlib.update_gateway( config_dir, rg_gateway_name, "port=31112", "driver=%s" % RG_DRIVER )

    # start the RG 
    rg_proc, rg_out_path = testlib.start_gateway( config_dir, RG_PATH, testconf.SYNDICATE_ADMIN, volume_name, rg_gateway_name )
    time.sleep(1)
    if rg_proc.poll() is not None:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("%s exited %s" % (RG_PATH, rg_proc.poll()))

    # put the file...
    exitcode, out = testlib.run( PUT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', gateway_name,
                                random_file_path, path )

    testlib.save_output( output_dir, "syndicate-put", out )

    if exitcode != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("Failed to touch %s" % path)

    # finish populating expected built-in xattrs 
    exitcode, out = testlib.run( STAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, "syndicate.conf"),
                                "-u", testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', getxattr_gateway_name,
                                path )

    testlib.save_output( output_dir, "syndicate-stat", out )
    if exitcode != 0:
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        raise Exception("Failed to stat %s" % path)

    # what's the file ID?
    out_lines = out.split("\n")
    file_version_line = filter( lambda l: l.startswith("version: "), out_lines)
    file_id_line = filter( lambda l: l.startswith("file_id: "), out_lines)

    assert len(file_id_line) == 1, "Missing 'file_id:' in output"
    assert len(file_version_line) == 1, "Missing 'version': in output"

    file_version = int(file_version_line[0].split(" ")[-1])
    file_id_hex = file_id_line[0].split(" ")[-1]
    if len(file_id_hex) != 16:
        file_id_hex = ("0" * (16 - len(file_id_hex))) + file_id_hex

    file_id_hex_parts = []
    for i in xrange(0, 4):
        file_id_hex_parts.append( file_id_hex[4*i] + file_id_hex[4*i+1] + file_id_hex[4*i+2] + file_id_hex[4*i+3] )

    # expected built-in attr for cached file data
    gateway_info = testlib.read_gateway( config_dir, gateway_name )
    getxattr_gateway_info = testlib.read_gateway( config_dir, getxattr_gateway_name )
    gateway_coord_id = gateway_info['g_id']
    getxattr_gateway_id = getxattr_gateway_info['g_id']
    volume_info = testlib.read_volume( config_dir, volume_name )
    file_cache_path = os.path.join( testlib.cache_dir( config_dir, volume_info['volume_id'], getxattr_gateway_id ), "/".join(file_id_hex_parts)) + "." + file_id_hex + "." + str(file_version)
    builtin_xattr_expected_values["user.syndicate_coordinator"] = gateway_name
    builtin_xattr_expected_values["user.syndicate_cached_file_path"] = file_cache_path

    # leave this gateway running, so it can answer xattr queries 
    ug_proc, ug_out_path = testlib.start_gateway( config_dir, COORD_PATH, testconf.SYNDICATE_ADMIN, volume_name, gateway_name, path, valgrind=True ) 
    time.sleep(5)

    # get built-in xattrs, individually, with the getxattr gateway
    for builtin_xattr in builtin_xattrs:
        exitcode, out = testlib.run( GETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                     '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', getxattr_gateway_name,
                                     path, builtin_xattr )

        testlib.save_output( output_dir, "syndicate-getxattr-%s" % builtin_xattr, out )
        if exitcode != 0:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            stop_and_save( output_dir, ug_proc, ug_out_path, "syndicate-coord")
            raise Exception("%s exited %s" % (GETXATTR_PATH, exitcode))

        if ("\n%s\n" % builtin_xattr_expected_values[builtin_xattr]) not in out:
            stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
            stop_and_save( output_dir, ug_proc, ug_out_path, "syndicate-coord")
            raise Exception("Output is missing '%s'" % builtin_xattr_expected_values[builtin_xattr])

    # read the file, to populate the cache 
    exitcode, out = testlib.run( CAT_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                 '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', getxattr_gateway_name,
                                 path, valgrind=True )

    testlib.save_output( output_dir, "syndicate-cat", out )
    if exitcode != 0: 
        stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
        stop_and_save( output_dir, ug_proc, ug_out_path, "syndicate-coord")
        raise Exception("%s exited %s" % (CAT_PATH, exitcode))

    stop_and_save( output_dir, rg_proc, rg_out_path, "syndicate-rg")
    stop_and_save( output_dir, ug_proc, ug_out_path, "syndicate-coord")

    # verify that the cached blocks are present in the reader's cache
    exitcode, out = testlib.run( GETXATTR_PATH, '-d2', '-f', '-c', os.path.join(config_dir, 'syndicate.conf'),
                                 '-u', testconf.SYNDICATE_ADMIN, '-v', volume_name, '-g', getxattr_gateway_name,
                                 path, "user.syndicate_cached_blocks" )

    testlib.save_output( output_dir, "syndicate-getxattr-user.syndicate_cached_blocks-coord", out )
    if exitcode != 0:
        raise Exception("%s exited %s" % (GETXATTR_PATH, exitcode))

    if "\n1111\n" not in out:
        raise Exception("Coordinator cached block output '1111' is missing")

    sys.exit(0)
