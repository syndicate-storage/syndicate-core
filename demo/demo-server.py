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

"""
Requires:
    * your ~/.syndicate must be set up and owned by a Syndicate admin user and is pointed to a "demo" MS
    * you have the Syndicate python package installed
    * you have the Syndicate automounter server installed
    * you have ~/.syndicate-amd set up 
"""

import os
import sys
import requests
import json
import logging
import tempfile
import subprocess
import urllib
import time
import base64

import syndicate.util.provisioning as provisioning
import syndicate.util.objects as object_stub
import syndicate.util.paths as paths
import syndicate.util.crypto as crypto
import syndicate.util.client as rpcclient
import syndicate.util.config as conf
import syndicate.util.storage as storage
import syndicate.syndicate as libsyndicate
import syndicate.protobufs.ms_pb2 as ms_pb2

from cryptography.fernet import Fernet


DEBUG = True

RG_PORT = 31111
UG_PORT = 31112
BLOCKSIZE = 65536

LIFETIME = 60 * 60 * 12 # 12 hours

EMAILS = {}     # email => {'date': creation date, 'password': password}

# taken from registrar/syndicate_signup.py
SIGNUP_URL = "https://syndicate-demo-signup.appspot.com"
SIGNUP_AUTH_SECRET = "ac5c015e354bf68a81df8177858064a296b3377d7da7828b71a393c7eee01a60ec840c2013485608c1732abe65927d87adfa159f36ec604638c147ccff777c80"

if os.environ.get("SIGNUP_URL", None) is not None:
    SIGNUP_URL = os.environ['SIGNUP_URL']

DRY_RUN = False
if os.environ.get("DRY_RUN", None) == '1':
    DRY_RUN = True

ONCE = False
if os.environ.get("ONCE", None) == '1':
    ONCE = True

def make_auth_headers():
    return {'Authorization': 'bearer {}'.format(SIGNUP_AUTH_SECRET)}


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

log = get_logger("demo")


def get_emails(count=20, offset=0):
    """
    Get the list of pending sign-up emails
    Returns the list of emails and their dates on success (as {'email': ..., 'date': ..., 'password': ...})
    Returns None on error
    """
    try:
        url = SIGNUP_URL + "/register?count={}&offset={}".format(count,offset)
        resp = requests.get(url, headers=make_auth_headers())
        if resp.status_code != 200:
            log.error("GET {}: HTTP {}".format(url, resp.status_code))
            return None 

        emails = json.loads( resp.text )
        return emails

    except Exception as e:
        if DEBUG:
            log.exception(e)

        return None


def get_all_emails():
    """
    Get all emails (pagenating)
    """
    all_emails = []
    offset = 0
    count = 20
    while True:
        emails = get_emails(count=count, offset=offset)
        if all_emails is None:
            log.error("Failed to get emails at offset={} count={}".format(offset, count))
            return None

        all_emails += emails
        if len(emails) == 0:
            break

        offset += count

    return all_emails


def refresh_emails():
    """
    Update our list of emails from the sign-up app
    Return {'new': new emails, 'expired': expired emails, 'user_info': all emails}
    """
    global EMAILS

    new = []
    expired = []

    # find new
    emails = get_all_emails()
    if emails is None:
        return {'error': 'Failed to get emails'}

    log.debug("Fetched {} emails".format(len(emails)))

    for email in emails:
        if not EMAILS.has_key(email['email']):
            # new
            new.append(email['email'])
    
    now = time.time()

    # find expired
    for email in EMAILS.keys():
        if EMAILS[email]['date'] + LIFETIME < now:
            expired.append(email['email'])

    log.debug("Got {} new emails, {} expired emails".format(len(new), len(expired)))

    return {'new': new, 'expired': expired, 'user_info': emails}


def sanitize_name(name):
    """
    Make a user_name string suitable for inclusion
    in a gateway or volume name.
    """
    return name.replace('@', '-0x40-').replace('+', '-0x2B-')


def make_provision_plan( new_users, expired_users ):
    """
    Make a provisioning plan for our new and expired users.
    * create volumes, UGs, and RGs for the new users
    * delete the volumes and gateways and users for the expired users

    Return the new new provisioning plan
    """
    
    provision_create_users = [{
        'username': user_name
    } for user_name in new_users]

    provision_delete_users = [{
        'username': user_name
    } for user_name in expired_users]

    provision_create_volumes = [{
        'name': sanitize_name('demo.volume-{}'.format(user_name)),
        'owner': user_name,
        'description': 'Demo volume for {}'.format(user_name),
        'blocksize': BLOCKSIZE,
        'private': False,
        'archive': False
    } for user_name in new_users]

    provision_delete_volumes = [{
        'name': sanitize_name('demo.volume-{}'.format(user_name))
    } for user_name in expired_users]

    provision_create_ug_gateways = [{
        'name': sanitize_name('demo.gateway-{}'.format(user_name)),
        'volume': sanitize_name('demo.volume-{}'.format(user_name)),
        'owner': user_name,
        'type': 'UG',
        'host': 'localhost',
        'port': UG_PORT,
    } for user_name in new_users]

    provision_create_rg_gateways = [{
        'name': sanitize_name('demo.gateway-{}'.format(user_name)),
        'volume': sanitize_name('demo.volume-{}'.format(user_name)),
        'owner': user_name,
        'type': 'RG',
        'host': 'localhost',
        'port': RG_PORT,
    } for user_name in new_users]

    provision_delete_ug_gateways = [{
        'volume': sanitize_name('demo.volume-{}'.format(user_name)),
        'type': 'UG',
        'host': 'localhost',
    } for user_name in expired_users]

    provision_delete_rg_gateways = [{
        'volume': sanitize_name('demo.volume-{}'.format(user_name)),
        'type': 'RG',
        'host': 'localhost',
    } for user_name in expired_users]

    provision_plan = {
        'users': {
            'create': provision_create_users,
            'delete': provision_delete_users,
        },
        'volumes': {
            'create': provision_create_volumes,
            'delete': provision_delete_volumes,
        },
        'gateways': {
            'create': provision_create_ug_gateways + provision_create_rg_gateways,
            'delete': provision_delete_ug_gateways + provision_delete_rg_gateways,
        },
    }

    return provision_plan


def run_provision_plan(provision_plan):
    """
    Invoke the automount server to run a provision plan.
    Return True on success
    Return False on error
    """
    syndicate_config = conf.get_config_from_argv(sys.argv)
    config_path = syndicate_config['config_path']

    provision_plan_txt = json.dumps(provision_plan)
    p = subprocess.Popen(["syndicate-amd-server", "-c", config_path, "provision"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    out, err = p.communicate(provision_plan_txt)
    p.wait()

    if p.returncode != 0:
        log.error("Failed to run `syndicate-amd-server provision`: exit code {}".format(p.returncode))
        log.error("Stdout:\n{}".format( '\n'.join( ['   {}'.format(l) for l in out.split('\n')] )))
        log.error("Stderr:\n{}".format( '\n'.join( ['   {}'.format(l) for l in err.split('\n')] )))
        return False

    return True


def upload_keys(new_emails, user_infos):
    """
    Save all private keys for the users we just provisioned
    (user and volume keys)

    Return True if they all succeed
    Return False if at least one fails
    """
    syndicate_config = conf.get_config_from_argv(sys.argv)
    pkeys = {}

    for user_name in new_emails:
        user_pkey = storage.load_private_key( syndicate_config, "user", user_name )
        if user_pkey is None:
            log.error("Automount daemon failed to produce key for {}".format(user_name))
            return False

        pkeys[user_name] = {
            'user_pkey': user_pkey.exportKey(),
        }

    for user_info in user_infos:
        user_name = user_info['email']
        user_password = user_info['password']
        if user_name not in new_emails:
            continue
       
        if len(user_password) == 0:
            # skip this user 
            log.debug("Skipping already-processed user {}".format(user_name))
            del pkeys[user_name]
            continue

        user_password = base64.urlsafe_b64encode(base64.b64decode(user_password))

        f = Fernet(user_password)
        pkeys[user_name]['user_pkey'] = f.encrypt(pkeys[user_name]['user_pkey'])

        # base64-encode (raw)
        pkeys[user_name]['user_pkey'] = base64.b64encode( base64.urlsafe_b64decode(pkeys[user_name]['user_pkey']) )

    log.debug("Upload key bundles for {} users".format(len(pkeys.keys())))

    for user_name in pkeys.keys():
        # send encrypted keys 
        try:
            log.debug("Upload keys for {}".format(user_name))
            req = requests.post(SIGNUP_URL + '/provision/{}'.format(urllib.quote(user_name)), headers=make_auth_headers(), 
                    data={'user_private_key': pkeys[user_name]['user_pkey']})

            if req.status_code != 200:
                if req.status_code != 202:
                    log.error("Failed to provision {}: HTTP {} ({})".format(user_name, req.status_code, req.text))
                
        except Exception as e:
            if DEBUG:
                log.exception(e)

            return False

    return True


def clear_expired( user_emails ):
    """
    Remove expired user state from the signup service
    """

    log.debug("Clear {} expired users".format(len(user_emails)))

    # go through all deleted emails and remove them from the signup system 
    for email in user_emails:
        try:
            log.debug("Delete expired email {}".format(email))
            req = requests.delete(SIGNUP_EMAIL + '/register?email={}'.format(urllib.quote(email)), headers=make_auth_headers())
            if req.status_code != 200:
                log.error("Failed to expire email {}".format(email))
                return False

        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.error("Failed to contact sign-up page to expire email {}".format(email))
            return False

    return True


def step():
    """
    Run one cycle of the main loop.
    Return True on success
    Return False on error
    """
    global EMAILS

    if os.path.exists("./demo_users.json"):
        log.info("Loading saved user info...")
        with open("./demo_users.json", "r") as f:
            saved_emails_txt = f.read()
            saved_emails = json.loads(saved_emails_txt)
            EMAILS = saved_emails

    log.info("Refreshing emails...")
    signup_info = refresh_emails()
    if 'error' in signup_info:
        log.error("Failed to refresh emails")
        return False

    new_emails = signup_info['new']
    expired_emails = signup_info['expired']
    user_info = signup_info['user_info']

    provision_plan = make_provision_plan(new_emails, expired_emails)
    log.debug("Provision plan\n{}".format(json.dumps(provision_plan, indent=4, sort_keys=True)))

    log.info("Running provision plan...")
    if not DRY_RUN:
        res = run_provision_plan(provision_plan)
        if not res:
            log.error("Failed to run provision plan")
            return False

    else:
        log.debug("Dry run; not actually running the provision step")

    log.info("Uploading keys...")
    res = upload_keys(new_emails, user_info)
    if not res:
        log.error("Failed to upload keys")
        return False

    log.info("Clearing expired users...")
    res = clear_expired( expired_emails )
    if not res:
        log.error("Failed to clear {} expired email(s)".format(len(expired_emails)))
        return False

    # remember which users we successfully activated
    for new_email in new_emails:
        for ui in user_info:
            if ui['email'] == new_email:
                EMAILS[new_email] = ui

    with open("./demo_users.json", "w") as f:
        f.write(json.dumps(EMAILS))

    return True

                
def main(argv):
    """
    Loop forever to process sign-ups and delete old emails.
    """
    delay = 0
    while True:
        
        step()
        if ONCE:
            return

        # wait 5 minutes before doing this loop
        deadline = time.time() + 300
        while time.time() < deadline:
            time.sleep(1)


if __name__ == "__main__":
    main(sys.argv)
