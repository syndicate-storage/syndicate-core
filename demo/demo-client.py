#!/usr/bin/python2

"""
   Copyright 2017 The Trustees of Princeton University

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
import requests
import logging
import jsonschema
import base64
import tempfile
import subprocess
import time
import random
import json 

from cryptography.fernet import Fernet

import syndicate.util.provisioning as provisioning
import syndicate.util.objects as object_stub
import syndicate.util.paths as paths
import syndicate.util.crypto as crypto
import syndicate.util.client as rpcclient
import syndicate.util.config as conf
import syndicate.util.storage as storage
import syndicate.syndicate as libsyndicate
import syndicate.protobufs.ms_pb2 as ms_pb2

DEBUG = True

# taken from registrar/syndicate_signup.py
SIGNUP_URL = "https://syndicate-demo-signup.appspot.com"
SIGNUP_AUTH_SECRET = "ac5c015e354bf68a81df8177858064a296b3377d7da7828b71a393c7eee01a60ec840c2013485608c1732abe65927d87adfa159f36ec604638c147ccff777c80"

if os.environ.get("SIGNUP_URL", None) is not None:
    SIGNUP_URL = os.environ['SIGNUP_URL']

def get_logger(name=None):
    """
    Make a singleton logger
    """
    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + '.%(thread)d) %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log


log = get_logger("demo_client")


def get_demo_payload(username, password):
    """
    Get the demo payload for this user.
    Return the payload on success
    Return None on error
    """
    try:
        req = requests.get(SIGNUP_URL + '/provision/{}'.format(username), headers={'authorization': 'bearer {}'.format(SIGNUP_AUTH_SECRET)})
        payload = req.json()
    except Exception as e:
        log.exception(e)
        return None

    payload_schema = {
        'type': 'object',
        'properties': {
            'user_pkey': {
                'type': 'string',
            },
            'gateway_pkey': {
                'type': 'string',
            },
            'user_cert': {
                'type': 'string',
            },
            'ug_cert': {
                'type': 'string',
            },
            'rg_cert': {
                'type': 'string',
            },
        },
        'required': [
            'user_pkey',
            'gateway_pkey',
            'user_cert',
            'ug_cert',
            'rg_cert'
        ]
    }

    try:
        jsonschema.validate(payload, payload_schema)
    except jsonschema.ValidationError:
        log.error("Invalid key data: {}".format(keys))
        return None

    # decrypt encrypted fields 
    password = base64.urlsafe_b64encode( base64.b64decode(password) )
    for encrypted_field in ['user_pkey', 'gateway_pkey']:
        f = Fernet(password)
        payload[encrypted_field] = f.decrypt(str(payload[encrypted_field]))

    # parse certificates 
    user_cert = ms_pb2.ms_user_cert()
    ug_cert = ms_pb2.ms_gateway_cert()
    rg_cert = ms_pb2.ms_gateway_cert()

    try:
        user_cert.ParseFromString(base64.b64decode(payload['user_cert']))
        ug_cert.ParseFromString(base64.b64decode(payload['ug_cert']))
        rg_cert.ParseFromString(base64.b64decode(payload['rg_cert']))

        payload['user_cert'] = user_cert
        payload['ug_cert'] = ug_cert
        payload['rg_cert'] = rg_cert

    except Exception as e:
        log.exception(e)
        return None

    return payload


def sanitize_name(name):
    """
    Make a user_name string suitable for inclusion
    in a gateway or volume name.
    """
    return name.replace('@', '-0x40-').replace('+', '-0x2B-')


def make_volume_info(username, demo_payload):
    """
    Make volume information to be passed into the syndicate automount client
    """
    volume_name = sanitize_name('demo.volume-{}'.format(username))

    volume_info = {
        volume_name: {
            'gateways': {
                '__pkey__': demo_payload['gateway_pkey'],
                demo_payload['ug_cert'].name: base64.b64encode(demo_payload['ug_cert'].SerializeToString()),
                demo_payload['rg_cert'].name: base64.b64encode(demo_payload['rg_cert'].SerializeToString()),
            },
            'users': {
                username: {
                    'cert': base64.b64encode(demo_payload['user_cert'].SerializeToString()),
                    'pkey': demo_payload['user_pkey'],
                },
            },
            'hints': {
                'gateways': {
                    demo_payload['ug_cert'].name: {
                        'mode': 'user-filesystem'
                    },
                },
            },
        },
    }

    return volume_info


def run_provision(volume_info_path):
    """
    Run the automount client to provision the volume
    Return True on success
    Return False on error
    """

    syndicate_config = conf.get_config_from_argv(sys.argv)
    config_path = syndicate_config['config_path']

    p = subprocess.Popen(["syndicate-amd", "--debug", "-c", config_path, "provision", volume_info_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    out, err = p.communicate()
    p.wait()

    if p.returncode != 0:
        log.error("Failed to run `syndicate-amd provision {}`: exit code {}".format(volume_info_path, p.returncode))
        log.error("Stdout:\n{}".format( '\n'.join( ['   {}'.format(l) for l in out.split('\n')] )))
        log.error("Stderr:\n{}".format( '\n'.join( ['   {}'.format(l) for l in err.split('\n')] )))
        return False

    return True


def provision_volume(volume_info):
    """
    Given volume info from make_volume_info(), instantiate it
    Return True on success
    Return False on error (caller should retry)
    """
    # save it
    volume_info_data = json.dumps(volume_info)
    rc = None
    path = None
    try:
        fd, path = tempfile.mkstemp()
        os.close(fd)

        with open(path, 'w') as f:
            f.write(volume_info_data)

        rc = run_provision(path)
        os.unlink(path)
    
    except Exception as e:
        log.exception(e)
        os.unlink(path)

    finally:
        if path is not None and os.path.exists(path):
            os.unlink(path)

    return rc


def main():
    """
    Go start up the volume
    """
    syndicate_config = conf.get_config_from_argv(sys.argv)
    args = syndicate_config['params']
    if len(args) != 2:
        print >> sys.stderr, "Usage: {} email password".format(sys.argv[0])
        return 1

    username = args[0]
    password = args[1]

    demo_payload = get_demo_payload(username, password)
    if demo_payload is None:
        print >> sys.stderr, "Failed to access demo service.  Please try again later."
        return 1

    volume_info = make_volume_info(username, demo_payload)
    timeout = 1.0

    print "Starting up Syndicate gateways..."
    while True:
        rc = provision_volume(volume_info)
        if rc:
            break

        # failure 
        print >> sys.stderr, "Failed to provision Syndicate volume; retrying in {} seconds".format(timeout)
        time.sleep(timeout)

        timeout = timeout * 2 + random.random() * timeout

    return 0


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
