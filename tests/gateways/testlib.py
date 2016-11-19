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
import json
import logging
import time
import requests

import testconf
import syndicate.util.config as conf
import syndicate.util.provisioning as provisioning
import syndicate.util.client as rpcclient

debug = True

def get_logger(name=None, debug=True):
    """
    Get a logger
    """

    level = logging.CRITICAL
    if debug:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + ') %(message)s' if debug else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log

log = get_logger("syndicate-testlib")
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
    Pass `stdin=True` to enable stdin
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
    stdout_path = "(fd)"
    env = {'SYNDICATE_DEBUG': '1'}

    if kw.has_key('stdin') and kw['stdin']:
        stdin_fd = subprocess.PIPE

    if kw.has_key('stdout_fd'):
        stdout_fd = kw['stdout_fd']
        stdout_path = "(fd %s)" % stdout_fd

    if kw.has_key('stdout_path'):
        stdout_path = kw['stdout_path']

    if kw.has_key('env'):
        env = kw['env']

    valgrind = False
    if 'valgrind' in kw.keys() and kw['valgrind']:
        args = ['--leak-check=full', path] + list(args)
        path = '/usr/bin/valgrind'

    print "$ %s > %s" % (" ".join( [path] + [str(a) for a in args] ), stdout_path) 
    prog = subprocess.Popen( [path] + [str(a) for a in args], shell=False, stdin=stdin_fd, stdout=stdout_fd, stderr=subprocess.STDOUT, env=env )
    if prog is None:
        raise Exception("Failed to start '%s'" % path)

    return prog


def finish( prog, out_path=None, stdin=None, valgrind=False ):
    """
    Finish up a program:
    * give it stdin
    * wait for stdout, stderr

    if out_path is not None, then return (output, prog return code)
    if valgrind is True, also check for valgrind errors.

    Otherwise, return exitcode on success
    """
    prog.communicate( input=stdin )
    prog.wait()

    output = None
    if out_path is not None:

        with open(out_path, "r") as f:
            output = f.read()

        if valgrind:
            rc = valgrind_check_output( output )
            if not rc:
                return (output, "valgrind error")

        return output, prog.returncode

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
    env = {'SYNDICATE_DEBUG': '1'}

    if kw.has_key('env'):
        env = kw['env']
        del kw['env']

    prog = start( path, *args, stdout_fd=out_fd, stdout_path=out_path, env=env, **kw )
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


def gateway_ping( portnum, attempts ):
    """
    Keep trying to ping a gateway until it comes online.
    Try at most $attempts times, waiting 1 second in between.
    """
    status_code = "UNKNOWN"
    for i in xrange(0, attempts):

        try:
            req = requests.get("http://localhost:%s/PING" % portnum)
            status_code = req.status_code
            assert status_code == 200
            return True

        except:
            print "# Ping http://localhost:%s/PING failed (status %s)" % (portnum, status_code)
            time.sleep(1.0)

    return False


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

    exitcode, out = run( testconf.SYNDICATE_TOOL, '-d', "--trust_public_key", "-c", os.path.join(tmpdir, 'syndicate.conf'), '--debug', 'setup', admin_email, admin_pkey_path, ms_url )
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
                         '-d',
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


def read_volume( config_dir, volume_name ):
    """
    Read a volume
    Return a dict with the volume attributes on success
    Raise on error
    """
    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'read_volume',
                        volume_name, env={})

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    try:
        ret = json.loads(out.strip())
    except:
        raise Exception("Invalid output:\n%s\n" % out)

    return ret



def add_test_gateway( config_dir, volume_name, gwtype, caps="ALL", driver=None, email=testconf.SYNDICATE_ADMIN, prefix='testgateway-', port=31111 ):
    """
    Create a gateway of a given type with a random way.
    Does both a create_gateway and update_gateway (which forces a volume-reload), so we test reloads each time.
    Return the name of the gateway
    """
    random_name = "%s%s-%s" % (prefix, gwtype, hex(random.randint(0, 2**32))[2:])
    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-d',
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'create_gateway',
                        'email=%s' % email,
                        'volume=%s' % volume_name,
                        'name=%s' % random_name,
                        'private_key=auto',
                        'port=%s' % port,
                        'type=%s' % gwtype)

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-d',
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


def read_gateway( config_dir, gateway_name ):
    """
    Read a gateway
    Return a dict with the gateway attributes on success
    Raise on error
    """
    exitcode, out = run(testconf.SYNDICATE_TOOL,
                        '-c', os.path.join(config_dir, 'syndicate.conf'),
                        'read_gateway',
                        gateway_name, env={})

    if exitcode != 0:
        print >> sys.stderr, out
        raise Exception("%s exited %s" % (testconf.SYNDICATE_TOOL, exitcode))

    try:
        ret = json.loads(out)
    except:
        raise Exception("Invalid output:\n%s\n" % out)

    return ret


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
                  '-d3',
                  '-f',
                  '-u', email,
                  '-v', volume_name,
                  '-g', gateway_name,
                  *extra_args, stdout_fd=out_fd, stdout_path=out_path, **kw )

    running_gateways.append( prog )
    return prog, out_path


def start_automount_server( config_dir, amd_server_path, email, port, *extra_args, **kw ):
    """
    Start the automount server
    Return a subprocess and a stdout path
    """
    out_fdes, out_path = tempfile.mkstemp(prefix='syndicate-test-')
    out_fd = os.fdopen(out_fdes, "w")

    if 'private_key' in kw.keys():
        pkey_path = kw['private_key']
    else:
        pkey_path, pkey_fd = tempfile.mkstemp(prefix='syndicate-pkey-')
        os.close(pkey_fd)
        os.system("openssl genrsa 4096 > \"%s\" 2>/dev/null" % pkey_path)

    prog = start( amd_server_path,
                  '-c', os.path.join(config_dir, 'syndicate.conf'),
                  '-d',
                  '-p', port,
                  '-k', pkey_path,
                  *extra_args, stdout_fd=out_fd, stdout_path=out_path, **kw )

    running_gateways.append( prog )
    return prog, out_path


def get_amd_logpath( config_dir ):
    return os.path.join(config_dir, 'amd_logs')


def start_automount_client( config_dir, amd_client_path, amd_server_port, amd_client_port, instance_id, *extra_args, **kw ):
    """
    Star the automount client
    Return a subprocess and a stdout path
    """
    out_fdes, out_path = tempfile.mkstemp(prefix='syndicate-test-')
    out_fd = os.fdopen(out_fdes, "w")

    if 'private_key' in kw.keys():
        pkey_path = kw['private_key']
    else:
        pkey_path, pkey_fd = tempfile.mkstemp(prefix='syndicate-pkey-')
        os.close(pkey_fd)
        os.system("openssl genrsa 4096 > \"%s\" 2>/dev/null" % pkey_path)

    if 'mounts' in kw.keys():
        mount_path = kw['mounts']
    else:
        mount_path = os.path.join(config_dir, 'mounts')
        if not os.path.exists( mount_path ):
            os.makedirs(mount_path)

    prog = start( amd_client_path,
                  '-c', os.path.join(config_dir, 'syndicate.conf'),
                  '-d',
                  '-s', 'localhost:%s' % amd_server_port,
                  '-p', str(amd_client_port),
                  '-M', mount_path,
                  '-l', get_amd_logpath(config_dir),
                  stdout_path=out_path )

    running_gateways.append( prog )
    return prog, out_path



def stop_gateway( proc, stdout_path, valgrind=False ):
    """
    Stop a gateway process
    Return (exitcode, stdout)
    if @valgrind is True, then return ("valgrind error", output) if there were memory errors
    """
    global running_gateways

    if proc.poll() is None:
        try:
            proc.send_signal( signal.SIGTERM )
        except:
            pass

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


def stop_automount_server( proc, stdout_path ):
    """
    Stop an automount server
    Return (exitcode, stdout)
    """
    if proc.poll() is None:
        try:
            proc.send_signal( signal.SIGTERM )
        except:
            pass

    exitcode = finish(proc)

    out = None
    with open(stdout_path, "r") as f:
        out = f.read()

    return (exitcode, out)


def stop_automount_client( proc, stdout_path ):
    """
    Stop an automount client
    Return (exitcode, stdout)
    """
    return stop_automount_server( proc, stdout_path )


def cache_dir( config_dir, volume_id, gateway_id ):
    """
    Get gateway-specific cache dir
    """
    return os.path.join(config_dir, "data", "%s" % volume_id, "%s" % gateway_id)


def staging_dir( config_dir, volume_id, gateway_id ):
    """
    Get gateway-specific staging dir
    """
    return os.path.join(config_dir, "data", "%s" % volume_id, "staging", "%s" % gateway_id )


def clear_cache( config_dir, volume_id=None, gateway_id=None ):
    """
    Clear cached data in a config dir
    DO NOT CALL UNLESS THE GATEWAY IS STOPPED

    TODO: clear the reader, but not the RG/AG cache
    """
    cache_dir = None 
    if volume_id is None and gateway_id is None:
        cache_dir = os.path.join(config_dir, "data")

    elif volume_id is not None and gateway_id is None:
        cache_dir = os.path.join(config_dir, "data", "%s" % volume_id)

    elif volume_id is not None and gateway_id is not None:
        cache_dir = os.path.join(config_dir, "data", "%s" % volume_id, "%s" % gateway_id )

    else:
        raise Exception("gateway ID given but not volume ID")

    if os.path.exists(cache_dir):
        print "$ rm -rf %s" % cache_dir
        shutil.rmtree(cache_dir)

    print "$ mkdir -p %s" % cache_dir
    os.makedirs( cache_dir, 0700 )
    return True


def make_tmp_file( size, pattern, dir="/tmp" ):
    """
    Make a temporary file with the given size and byte pattern.
    """
    assert len(pattern) > 0

    fd, path = tempfile.mkstemp( dir=dir )
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


def make_random_file( size, dir="/tmp" ):
    """
    Make a temporary file with a random byte pattern
    """
    fd, path = tempfile.mkstemp( dir=dir )
    ffd = os.fdopen(fd, "w")

    multipler = size / 10000
    if multipler == 0:
        multipler = 1

    if multipler > 100000:
        multipler = 100000

    pattern = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * multipler)
    random.shuffle(pattern)
    suffix = pattern[0:size%len(pattern)]
    l = 0

    while l + len(pattern) < size:
        random.shuffle(pattern)
        ffd.write("".join(pattern))
        l += len(pattern)

    ffd.write("".join(suffix))
    ffd.flush()
    os.fsync(fd)
    print "$ # Temporary %s-byte random file at %s" % (size, path)
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
