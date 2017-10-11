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
import errno
import cStringIO
import traceback
import signal
import json
import threading
import cPickle as pickle
import imp
import requests
from syndicate.protobufs.sg_pb2 import DriverRequest, Manifest

driver_shutdown = None


def do_driver_shutdown():
    """
    gracefully shut down
    """
    global driver_shutdown

    log_debug("Worker exiting")

    if driver_shutdown is not None:
        rc = driver_shutdown()
        if type(rc) in [int, long]:
            sys.exit(rc)
        else:
            sys.exit(0)

    else:
        sys.exit(0)


def get_read_method(f):
    """
    Given either a file or a socket,
    get the method that returns data
    """
    if hasattr(f, "read"):
        return f.read
    elif hasattr(f, "recv"):
        return f.recv
    else:
        raise Exception("Neither a file nor a socket")


def sock_recvline(soc, maxsize):
    """
    Receive a line of data (including newline)
    from a socket
    """
    s = cStringIO.StringIO()
    count = 0
    while count < maxsize:
        c = soc.recv(1)
        s.write(c)
        count += 1
        if c == '\n':
            break

    return s.getvalue()


def get_readline_method(f):
    """
    Given either a file or a socket,
    get the method that returns a line of data.
    """
    if hasattr(f, "readline"):
        return f.readline
    elif hasattr(f, "recv"):
        return lambda size: sock_recvline(f, size)
    else:
        raise Exception("Neither a file nor a socket")


def get_write_method(f):
    """
    Given either a file or a socket,
    get the method that sends data.
    """
    if hasattr(f, "write"):
        return f.write
    elif hasattr(f, "send"):
        return f.send
    else:
        raise Exception("Neither a file nor a socket")


def read_string(f):
    """
    Read a null-terminated string from file f.
    """
    s = cStringIO.StringIO()
    read_method = get_read_method(f)
    while True:

        c = read_method(1)
        if c == '\0':
            break

        s.write(c)

    return s.getvalue()


def read_int(f):
    """
    Read an integer from file f, as a newline-terminated string
    Return the int on success
    Return None on error
    """

    readline_method = get_readline_method(f)
    # read the int
    try:
        i = readline_method(100)
    except Exception, e:
        log_error(traceback.format_exc())
        log_error("Failed to read integer")
        return None

    if len(i) == 0:
        # gateway exit
        do_driver_shutdown()

    if i[-1] != '\n':
        # invalid line
        log_error("Integer too long: '%s'" % i)
        return None

    try:
        i = int(i.strip())
    except Exception, e:
        log_error("Invalid integer: '%s'" % i)
        return None

    return i


def read_data(f, size):
    """
    Read a newline-terminated data stream from f, up to size.
    Return the chunk on success
    Return None on error
    """
    read_method = get_read_method(f)
    try:
        chunk = read_method(size+1)
    except Exception:
        log_error("Failed to read chunk")
        return None

    if len(chunk) == 0:
        # gateway exit
        do_driver_shutdown()

    if len(chunk) != size+1:
        # invalid chunk
        raise Exception("Data too short (size = %s, chunk = %s)" % (size, len(chunk)))

    if chunk[-1] != '\n':
        # invalid chunk
        raise Exception("Data too long (size = %s, chunk = %s, terminator = '%s')" % (size, len(chunk), chunk[-1]))

    chunk = chunk[:len(chunk)-1]
    return chunk


def read_chunk(f):
    """
    Get a chunk of data from a file descriptor.
    A chunk is encoded by its length, a newline, and data.
    """

    chunk_len = read_int(f)
    if chunk_len is None:
        log_error("Failed to read chunk length")
        do_driver_shutdown()

    chunk = read_data(f, chunk_len)
    return chunk


def read_request(f):
    """
    Read a chunk from file f that
    contains a DriverRequest string.
    Return the deserialized DriverRequest on success
    Shut down the driver on error.
    """
    req_chunk = read_chunk(f)
    if req_chunk is None:
        log_error("Failed to read driver request chunk")
        do_driver_shutdown()

    try:
        driver_req = DriverRequest()
        driver_req.ParseFromString(req_chunk)
    except Exception:
        log_error("Failed to parse driver request")
        do_driver_shutdown()

    return driver_req


def request_to_storage_path(request):
    """
    Create a storage path for a request.
    It will be prefixed the volume ID, then
    inode, then path, version, and either block ID or version
    or manifest timestamp (depending on what kind of
    request this is).

    If this request is a rename hint, then no path will be returned.

    Return the string on success
    """

    prefix = "%s/%X" % (request.volume_id, request.file_id)

    if request.request_type == DriverRequest.BLOCK:
        prefix = os.path.join(prefix, "%s/%s" % (request.block_id, request.block_version))

    elif request.request_type in [DriverRequest.MANIFEST, DriverRequest.RENAME_HINT]:
        prefix = os.path.join(prefix, "manifest/%s.%s" % (request.manifest_mtime_sec, request.manifest_mtime_nsec))

    else:
        log_error("Invalid driver request type '%s'" % request.request_type)
        do_driver_shutdown()

    return prefix


def write_int(f, i):
    """
    Send back an integer to the main Syndicate daemon.
    """
    write_method = get_write_method(f)
    write_method("%s\n" % i)


def write_data(f, data):
    """
    Send back a string of data to the main Syndicate daemon.
    """
    write_method = get_write_method(f)
    write_method("%s\n" % data)


def write_chunk(f, data):
    """
    Send back a length, followed by a newline, followed by a string
    of data to Syndicate.
    """
    write_method = get_write_method(f)
    write_method("%s\n%s\n" % (len(data), data))


def request_byte_offset(request):
    """
    Calculate a DriverRequest's byte offset.
    Use the byte offset from the I/O hints if given;
    otherwise assume it's on a block boundary.
    Return None if the request is not for a block
    """

    if hasattr(request, "io_type") and hasattr(request, "offset") and request.io_type in [DriverRequest.READ, DriverRequest.WRITE]:
        # gateway-given offset hint
        return request.offset

    return None


def request_byte_len(request):
    """
    Calculate a DriverRequest's byte offset.
    Use the byte offset from the I/O hints if given;
    otherwise assume it's on a block boundary.
    Return None if the request is not for a block
    """

    if hasattr(request, "io_type") and hasattr(request, "len") and request.io_type in [DriverRequest.READ, DriverRequest.WRITE]:
        # gateway-given length hint
        return request.len

    return None


def request_path(request):
    """
    Get the path of the request
    """
    return str(request.path)


def request_new_path(request):
    """
    Get the new_path of the request, if it's a rename hint
    """
    if request.new_path is None:
        return None

    return str(request.new_path)


def request_type(request):
    """
    Get the type of request.
    Return as a string.
    """
    if request.request_type == DriverRequest.MANIFEST:
        return "manifest"

    elif request.request_type == DriverRequest.BLOCK:
        return "block"

    elif request.request_type == DriverRequest.RENAME_HINT:
        return "rename_hint"

    else:
        log_error("Invalid driver request type '%s'" % request.request_type)
        do_driver_shutdown()


def path_join(a, *b):
    """
    Join two or more paths, even if any of them are absolute.
    """
    parts = [p.strip("/") for p in b]
    return os.path.join(a, *parts)


def make_metadata_command(cmd, ftype, mode, size, path, read_ttl=5000, write_ttl=0):
    """
    Generate a metadata command structure (useful for crawling datasets).
    @cmd must be any of 'create', 'update', 'delete', or 'finish'
    @ftype must be either 'file' or 'directory'
    @path cannot have any newlines
    @size will be ignored for directories, and will only be processed on 'create' or 'update'

    Returns a command structure on success.
    Returns None if any of the above conditions are not met.
    """

    if ftype != 'file':
        size = 4096

    cmd_table = {
        "create": "C",
        "put":    "P",
        "update": "U",
        "delete": "D",
        "finish": "F",
    }

    ftype_table = {
        "file": "F",
        "directory": "D"
    }

    ret = {
        "cmd": cmd_table.get(cmd),
        "ftype": ftype_table.get(ftype),
        "mode": mode,
        "size": size,
        "path": path,
        "read_ttl": read_ttl,
        "write_ttl": write_ttl
    }

    if not check_metadata_command(ret):
        return None

    return ret


def make_metadata_delete_command(path):
    """
    Make a delete command (helpful wrapper around make_metadata_command)
    """
    return make_metadata_command("delete", "file", 0555, 0, path)


def check_metadata_command(cmd_dict):
    """
    Given a metadata command structure, verify that it is well-formed.
    Return True if so
    Return False if not
    """

    if type(cmd_dict) != dict:
        return False

    for key in ["cmd", "ftype", "mode", "size", "path", "read_ttl", "write_ttl"]:
        if not cmd_dict.has_key(key):
            return False

    if cmd_dict['cmd'] not in ['C', 'P', 'U', 'D', 'F']:
        return False

    if cmd_dict['ftype'] not in ['F', 'D']:
        return False

    if '\n' in cmd_dict['path']:
        return False

    return True


def write_metadata_command(f, cmd_dict):
    """
    Send back a metadata command for the gateway to send to the MS.
    Valid values for @cmd are "create", "update", or "delete"
    Valid values for @ftype are "file", "directory"
    @mode is the permission bits
    @size is the size of the file (ignored for directories)
    @path is the absolute path to the file or directory

    Raises an exception on invalid input.
    """

    if not check_metadata_command(cmd_dict):
        raise Exception("Malformed command: %s" % cmd_dict)

    lines = [
        "%s\n" % cmd_dict['cmd'],
        "%s 0%o %s %s %s\n" % (cmd_dict['ftype'], cmd_dict['mode'], cmd_dict['size'], cmd_dict['read_ttl'], cmd_dict['write_ttl']),
        "%s\n" % cmd_dict['path'],
        "0\n"
    ]

    serialized_buf = "".join(lines)
    write_method = get_write_method(f)
    write_method("%s:%s" % (len(serialized_buf), serialized_buf))


def crawl(cmd_dict):
    """
    Rendezvous with the gateway: send it a metadata command,
    and get back the result code of the gateway's attempt
    at processing it.

    Returns the integer code, or raises an exception if
    the command dict is malformed.
    """
    global crawl_rendezvous_func
    return crawl_rendezvous_func(cmd_dict)


def default_crawl_rendezvous(cmd_dict):
    """
    Default implementation of the crawl rendezvous function
    """
    write_metadata_command(sys.stdout, cmd_dict)
    sys.stdout.flush()

    rc = read_int(sys.stdin)
    return rc


# default crawl implementation
crawl_rendezvous_func = default_crawl_rendezvous

def set_crawl_rendezvous_func(sink_func):
    """
    Set the global function that will accept crawl command data
    from the AG driver, feed it to the AG, and give back the
    AG's response.

    The sink_func() must take a command dict as its only argument,
    and return a numerical return code.
    """
    global crawl_rendezvous_func
    crawl_rendezvous_func = sink_func


def get_gateway_id():
    """
    What's our gateway ID? Should be passed from the environment.
    """
    gwid = os.environ.get("SYNDICATE_GATEWAY_ID")
    if gwid is None:
        raise Exception("BUG: SYNDICATE_GATEWAY_ID is not set")

    try:
        gwid = int(gwid)
    except:
        raise Exception("BUG: SYNDICATE_GATEWAY_ID is '%s', expected int" % gwid)

    return gwid


def get_volume_id():
    """
    What's our volume ID? Should be passed from the environment.
    """
    vid = os.environ.get("SYNDICATE_VOLUME_ID")
    if vid is None:
        raise Exception("BUG: SYNDICATE_VOLUME_ID is not set")

    try:
        vid = int(vid)
    except:
        raise Exception("BUG: SYNDICATE_VOLUME_ID is '%s', expected int" % vid)

    return vid


def get_user_id():
    """
    What's our user ID? Should be passed from the environment.
    """
    uid = os.environ.get("SYNDICATE_USER_ID")
    if uid is None:
        raise Exception("BUG: SYNDICATE_USER_ID is not set")

    try:
        uid = int(uid)
    except:
        raise Exception("BUG: SYNDICATE_USER_ID is '%s', expected int" % uid)

    return uid


def get_config_path():
    """
    What's our gateway's config path?  Should be passed from the environment.
    """
    config_path = os.environ.get("SYNDICATE_CONFIG_PATH")
    if config_path is None:
        raise Exception("BUG: SYNDICATE_CONFIG_PATH is not set")

    return config_path


def get_ipc_root():
    """
    Where are the gateway/driver IPC structures stored?
    """
    ipc_root = os.environ.get("SYNDICATE_IPC_PATH")
    if ipc_root is None:
        raise Exception("BUG: SYNDICATE_IPC_PATH is not set")

    return ipc_root


def log_error(msg):
    """
    Synchronously log an error message
    """
    try:
        # stderr may be bad when the gateway is not started from a console
        print >> sys.stderr, "[Driver %s ERROR] %s" % (os.getpid(), msg)
        sys.stderr.flush()
    except:
        pass


def log_debug(msg):
    """
    Synchronously log a debug message
    """
    try:
        # stderr may be bad when the gateway is not started from a console
        print >> sys.stderr, "[Driver %s DEBUG] %s" % (os.getpid(), msg)
        sys.stderr.flush()
    except:
        pass


driver_shutdown = None
driver_shutdown_lock = threading.Semaphore(1)


# die on a signal
def sig_die(signum, frame):
    global driver_shutdown, driver_shutdown_lock

    if driver_shutdown is not None:
        # leave this locked to prevent subsequent calls
        driver_shutdown_lock.acquire()
        driver_shutdown()

    sys.exit(0)


# is an object callable?
def is_callable(obj):
    return hasattr(obj, "__call__")


# does a module have a method?
def has_method(mod, method_name):
    return hasattr(mod, method_name) and is_callable(getattr(mod, method_name, None))


# fail before startup
def do_fail(exitrc):
    print "1"

    try:
        # stderr may be bad when the gateway is not started from a console
        sys.stderr.flush()
    except:
        pass

    sys.stdout.flush()
    sys.exit(exitrc)


def driver_setup(operation_modes, expected_callback_names, default_callbacks={}):
    """
    Set up a gateway driver:
    * verify that the operation mode is supported (i.e. the operation
    mode is present in operation_modes)
    * install signal handlers for shutting down the driver, and calling
    the driver_shutdown() method.
    * load configuration, secrets, and code.
    * validate configuration, secrets, and code (i.e. verify that
    the config and secrets are well-formed, and that the code defines
    a callback for each method names in expected_callback_names).
    * run the driver_init() method.

    Return (operation mode, driver module) on success
    Signal the parent process and exit with a non-zero exit code on failure:
    * return 1 and exit 1 on misconfiguration
    * return 1 and exit 2 on failure to initialize
    * return 2 and exit 0 if the driver does not implement the requested operation mode
    """

    # die on SIGINT
    signal.signal(signal.SIGINT, sig_die)

    # usage: $0 operation_mode
    if len(sys.argv) != 2:
        log_error("Usage: %s operation_mode" % sys.argv[0])

        # tell the parent that we failed
        do_fail(1)

    usage = sys.argv[1]

    if usage not in operation_modes:
        log_error("Usage: %s operation_mode" % sys.argv[0])

        # tell the parent that we failed
        do_fail(1)

    methods = []
    for i in xrange(0, len(operation_modes)):
        if operation_modes[i] == usage:
            methods.append(expected_callback_names[i])

    # on stdin: config and secrets (as two separate null-terminated strings)
    config_len = read_int(sys.stdin)
    if config_len is None:
        do_fail(1)

    config_str = read_data(sys.stdin, config_len)
    if config_str is None:
        do_fail(1)

    secrets_len = read_int(sys.stdin)
    if secrets_len is None:
        do_fail(1)

    secrets_str = read_data(sys.stdin, secrets_len)
    if secrets_str is None:
        do_fail(1)

    driver_len = read_int(sys.stdin)
    if driver_len is None:
        do_fail(1)

    driver_str = read_data(sys.stdin, driver_len)
    if driver_str is None:
        do_fail(1)

    CONFIG = {}
    SECRETS = {}

    # config_str should be a JSON dict
    try:
        CONFIG = json.loads(config_str)
    except Exception, e:
        log_error("Failed to load config '{}'".format(config_str))
        log_error(traceback.format_exc())

        # tell the parent that we failed
        do_fail(2)

    # secrets_str should be a JSON dict
    try:
        SECRETS = json.loads(secrets_str)
    except Exception, e:
        log_error("Failed to load secrets '{}'".format(config_str))
        log_error(traceback.format_exc())

        # tell the parent that we failed
        do_fail(2)

    # driver should be a set of methods
    driver_mod = imp.new_module("driver_mod")
    try:
        exec driver_str in driver_mod.__dict__
    except Exception, e:
        log_error("Failed to load driver")
        log_error(traceback.format_exc())

        # tell the parent that we failed
        do_fail(2)

    # verify that the driver methods are defined
    fail = False
    for method_name in methods:
        if not has_method(driver_mod, method_name):
            if not default_callbacks.has_key(method_name):
                fail = True
                log_error("No method '%s' defined" % method_name)

            elif default_callbacks[method_name] is None:
                # no method implementation; fall back to the gateway
                log_error("No implementation for '%s'" % method_name)
                print "2"
                sys.exit(0)

            else:
                log_error("Using default implementation for '%s'" % method_name);
                setattr(driver_mod, usage, default_callbacks[method_name])

    if fail:
        do_fail(2)

    # remember generic shutdown so the signal handler can use it
    if has_method(driver_mod, "driver_shutdown"):
        global driver_shutdown
        driver_shutdown = driver_mod.driver_shutdown

    # do our one-time init, if given
    if not fail and has_method(driver_mod, "driver_init"):
        try:
            fail = not driver_mod.driver_init(CONFIG, SECRETS)
        except Exception:
            log_error("driver_init raised an exception")
            log_error(traceback.format_exc())
            fail = True

        if fail not in [True, False]:

            # indicates a bug
            fail = True

    if fail:
        do_fail(2)

    driver_mod.CONFIG = CONFIG
    driver_mod.SECRETS = SECRETS
    return (usage, driver_mod)
