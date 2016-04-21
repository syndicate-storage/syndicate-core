#!/usr/bin/env python

"""
   Copyright 2015 The Trustees of Princeton University

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
import tempfile
import random
import signal
import shutil
import atexit

import testconf
import syndicate.util.config as conf
import syndicate.util.provisioning as provisioning
import syndicate.util.client as rpcclient

log = conf.log
running_gateways = []

def atexit_gateway_shutdown():
    """
    Shut down all running gateways on exit.
    """
    global running_gateways
    for gw in running_gateways:
        try:
            gw.send_signal( signal.SIGTERM )
            log.debug("Sent SIGTERM to gateway %s" % gw.pid)
        except:
            continue

        try:
            exitcode = finish( gw )
        except:
            continue


def start( path, *args, **kw ):
    """
    Start a program
    Pass `stdin=...` to feed a string as stdin
    Pass `valgrind=True` to run in valgrind.
    Return subprocess on success
    Return None on error
    """
     
    if not os.path.exists( path ):
        log.error("Not found: %s" % path )
        return None

    stdin_fd = None
    stdout_fd = subprocess.PIPE
    stdin = None
    if kw.has_key('stdin'):
        stdin_fd = subprocess.PIPE
        stdin = kw['stdin']

    if kw.has_key('stdout_fd'):
        stdout_fd = kw['stdout_fd']
 
    valgrind = False
    if 'valgrind' in kw.keys() and kw['valgrind']:
        args = ['--leak-check=full', path] + list(args)
        path = '/usr/bin/valgrind'

    print "$ %s" % (" ".join( [path] + [str(a) for a in args] )) 
    prog = subprocess.Popen( [path] + [str(a) for a in args], shell=False, stdin=stdin_fd, stdout=stdout_fd, stderr=subprocess.STDOUT )
    return prog


def finish( prog, stdin=None ):
    """
    Finish up a program:
    * give it stdin
    * wait for stdout, stderr

    Return exitcode on success
    """
    prog.communicate( input=stdin )
    prog.wait()
    return prog.returncode


def run( path, *args, **kw ):
    """
    Run a program, and gather its results.
    Return (exitcode, stdout+stderr) on success
    Return ("valgrind error", stdout+stderr) if @valgrind is True and there were valgrind errors
    Return (None, None) on error
    """
   
    out_fdes, out_path = tempfile.mkstemp(prefix='syndicate-test-')
    out_fd = os.fdopen(out_fdes, "w")

    prog = start( path, *args, stdout_fd=out_fd, **kw )
    if prog is None:
        return (None, None)
 
    valgrind = False
    if 'valgrind' in kw.keys() and kw['valgrind']:
        valgrind = True

    stdin = None
    if kw.has_key('stdin'):
        stdin_fd = subprocess.PIPE
        stdin = kw['stdin']

    exitcode = finish( prog, stdin=stdin )
    out_fd.close()
    
    with open(out_path, "r") as f:
        output = f.read()

    if valgrind:
        rc = valgrind_check_output( output )
        if not rc:
            return ("valgrind error", output)

    return exitcode, output


def valgrind_check_output( out ):
    """
    Verify that there were no memory-related problems in the test output
    (no invalid reads or writes)
    """

    errors = [
        "Invalid read of size",
        "Invalid write of size",
        "Conditional jump or move depends on uninitialised value",
        "Uninitialised value was created by a heap allocation"
    ]

    # find the start of our output
    # (i.e. ignore libc weirdness)
    start_preamble = "### Syndicate gateway starting up... ###"
    out_offset = out.find("### Syndicate gateway starting up... ###")
    if out_offset < 0:
        raise Exception("Gateway did not start up")

    out_offset += len(start_preamble)

    for error in errors:
        if error in out[out_offset:]:
            return False

    return True

   
def test_setup( ms_url=testconf.SYNDICATE_MS, admin_email=testconf.SYNDICATE_ADMIN, admin_pkey_path=testconf.SYNDICATE_PRIVKEY_PATH, suffix="" ):
    """
    Set up a test config directory.
    Return the (config dir, test output dir) on success.
    """
    tmpdir = tempfile.mkdtemp( prefix="syndicate-test-", dir="/tmp" ) + suffix
    test_output_dir = os.path.join( tmpdir, "test_output" )

    exitcode, out = run( testconf.SYNDICATE_TOOL, "--trust_public_key", "-c", os.path.join(tmpdir, 'syndicate.conf'), '--debug', 'setup', admin_email, admin_pkey_path, ms_url )
    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    os.makedirs( test_output_dir )
    atexit.register( atexit_gateway_shutdown )
    return (tmpdir, test_output_dir)


def save_output( test_output_dir, name, output ):
    """
    Save the results of a test
    """
    out_path = os.path.join(test_output_dir, name )
    with open(out_path, "w") as f:
        f.write(output)
        f.flush()
        os.fsync(f.fileno())

    print '$ cat "%s"' % out_path


def add_test_volume( config_dir, email=testconf.SYNDICATE_ADMIN, blocksize=4096, prefix="testvolume-" ):
    """
    Create a volume with a random name.
    Return the name of the volume.
    """
    random_name = prefix + hex(random.randint(0,2**32))[2:] 
    exitcode, out = run( testconf.SYNDICATE_TOOL,
                         '-c', os.path.join(config_dir, 'syndicate.conf'),
                         'create_volume',
                         'name=%s' % random_name,
                         'description="test volume"',
                         'blocksize=%s' % blocksize,
                         'email=%s' % email)

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    return random_name


def add_test_gateway( config_dir, volume_name, gwtype, caps="ALL", driver=None, email=testconf.SYNDICATE_ADMIN, prefix='testgateway-' ):
    """
    Create a gateway of a given type with a random way.
    Does both a create_gateway and update_gateway (which forces a volume-reload), so we test reloads each time.
    Return the name of the gateway
    """
    random_name = "%s%s-%s" % (prefix, gwtype, hex(random.randint(0, 2**32))[2:])
    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'create_gateway',
                        'email=%s' % email,
                        'volume=%s' % volume_name,
                        'name=%s' % random_name,
                        'private_key=auto',
                        'type=%s' % gwtype)

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'update_gateway',
                        random_name,
                        'caps=%s' % caps)

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    return random_name


def update_gateway( config_dir, gateway_name, *args ):
    """
    Update a gateway
    Return True on success
    Raise on error
    """
    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'update_gateway',
                        gateway_name,
                        *args)

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    return True


def provision_volume( config_dir, volume_name, description, blocksize, email, **attrs ):
    """
    Provision a volume--ensure it exists and is consistent with the given information
    Returns the latest volume state.
    """
    config = conf.get_config_from_file( os.path.join(config_dir, "syndicate.conf"))
    client = rpcclient.make_rpc_client( config, caller_username=email )
    created, updated, volume = provisioning.ensure_volume_exists( client, volume_name, description, blocksize, email, **attrs )
    return volume


def provision_gateway( config_dir, gateway_type, email, volume_name, gateway_name, host, port, caller_email=None, **attrs ):
    """
    Provision a gateway--ensure it exists and is consistent with the given information
    Returns the latest gateway state
    """
    config = conf.get_config_from_file( os.path.join(config_dir, "syndicate.conf" ))
    client = rpcclient.make_rpc_client( config, caller_username=caller_email )
    created, updated, gateway = provisioning.ensure_gateway_exists( client, gateway_type, email, volume_name, gateway_name, host, port, **attrs )
    return gateway


def start_gateway( config_dir, gateway_path, email, volume_name, gateway_name, *extra_args, **kw ):
    """
    Run a gateway.
    Return the subprocess and stdout path, and track the running gateway
    """
    global running_gateways

    out_fdes, out_path = tempfile.mkstemp(prefix='syndicate-test-')
    out_fd = os.fdopen(out_fdes, "w")

    prog = start( gateway_path,
                  '-c', os.path.join(config_dir, 'syndicate.conf'),
                  '-d2',
                  '-f',
                  '-u', email,
                  '-v', volume_name,
                  '-g', gateway_name,
                  *extra_args, stdout_fd=out_fd, **kw )

    running_gateways.append( prog )
    return prog, out_path


def stop_gateway( proc, stdout_path, valgrind=False ):
    """
    Stop a gateway process
    Return (exitcode, stdout)
    if @valgrind is True, then return ("valgrind error", output) if there were memory errors
    """
    global running_gateways
    proc.send_signal( signal.SIGTERM )
    exitcode = finish( proc )
    running_gateways.remove(proc)
   
    out = None
    with open(stdout_path, "r") as f:
        out = f.read()

    if valgrind:

        rc = valgrind_check_output( out )
        if not rc:
            return ("valgrind error", out )

    return (exitcode, out)


def clear_cache( config_dir ):
    """
    Clear cached data in a config dir
    DO NOT CALL UNLESS THE GATEWAY IS STOPPED
    """
    cache_dir = os.path.join(config_dir, "data")
    shutil.rmtree(cache_dir)

    os.makedirs( cache_dir, 0700 )
    return True


def make_tmp_file( size, pattern ):
    """
    Make a temporary file with the given size and byte pattern.
    """
    assert len(pattern) > 0

    fd, path = tempfile.mkstemp()
    ffd = os.fdopen(fd, "w")

    suffix = pattern[0:size%len(pattern)]
    l = 0

    while l + len(pattern) < size:
        ffd.write(pattern)
        l += len(pattern)

    ffd.write(suffix)
    ffd.flush()
    os.fsync(fd)
    print "$ # Temporary %s-byte file at %s" % (size, path)
    return path


def get_benchmark_data( out ):
    """
    Find benchmark data in stdout.
    Return the list of times
    """
    lines = out.split("\n")
    for l in lines:
        l = l.strip()
        if l.startswith("@@@@@") and l.endswith("@@@@@"):
            l = l.strip("@")
            return [float(x) for x in l.split(",")]

    return None
