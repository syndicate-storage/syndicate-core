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

from cryptography.fernet import Fernet

DEBUG = True

# taken from registrar/syndicate_signup.py
SIGNUP_URL = "https://syndicate-demo-signup.appspot.com"

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


def get_private_keys(username, password):
    """
    Get the private keys from the sign-up service, and decrypt them
    Return {'user_private_key': ..., 'volume_private_key': ...} on success
    Return None on error
    """
    try:
        req = requests.get(SIGNUP_URL + '/provision/{}'.format(username))
        keys = req.json()
    except Exception as e:
        log.exception(e)
        return None

    try:
        jsonschema.validate(keys, {'type': 'object', 'properties': {'user_private_key': {'type': 'string'}, 'volume_private_key': {'type': 'string'}}, 'required': ['user_private_key', 'volume_private_key']})
    except jsonschema.ValidationError:
        log.error("Invalid key data: {}".format(keys))
        return None

    # decrypt 
    f = Fernet(password)
    user_private_key = f.decrypt(keys['user_private_key'])
    volume_private_key = f.decrypt(keys['volume_private_key'])

    return {'user_private_key': user_private_key, 'volume_private_key': volume_private_key}



