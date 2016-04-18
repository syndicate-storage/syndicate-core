#!/usr/bin/env python

"""
   Copyright 2013 The Trustees of Princeton University

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

# NOTE: shared between the MS and the Syndicate python package

import os

try:
   import syndicate.protobufs.ms_pb2 as ms_pb2
except:
   import protobufs.ms_pb2 as ms_pb2


try:
   import syndicate.client.common.log as Log
   log = Log.get_logger()
except:
   import logging as log

# configuration parameters

# MS
MS_PROTO = "http://"
MS_URL = ""
ADMIN_ID = 0

# NOTE: The MS is configured using the MS_APP_* environmental variables which
# are set in the in app.yaml file.  app.yaml is created from app.yamlin by
# configure_ms.mk when building from source, or by other means when the MS is
# distributed in binary form.

SYNDICATE_NAME = str(os.environ.get( "MS_APP_NAME", "syndicate-ms" ))

ADMIN_EMAIL = str(os.environ.get( "MS_APP_ADMIN_EMAIL", "syndicate-ms@example.com" ))
ADMIN_PUBKEY = str(os.environ.get( "MS_APP_ADMIN_PUBLIC_KEY", "" ))

SYNDICATE_PRIVKEY = str(os.environ.get( "MS_APP_PRIVATE_KEY", "" ))
SYNDICATE_PUBKEY = str(os.environ.get( "MS_APP_PUBLIC_KEY", "" ))

# MS_APP_PUBLIC_HOST does not need to be set in all cases, only for 
# for publicly-routable deployments outside of Google AppEngine or Appscale.
#
# The order of preference for setting MS_APP_PUBLIC_HOST is:
# * public hostname on Google AppEngine
# * $MS_PUBLIC_HOST, if defined
# * $SERVER_NAME, if defined
# * "localhost"

MS_HOST = str(os.environ.get( "MS_APP_PUBLIC_HOST", "" ))

if len(MS_HOST) == 0:
    MS_HOST = str(os.environ.get("SERVER_NAME", "localhost"))

MS_HOSTPORT = "%s:%s" % (MS_HOST, str(os.environ.get("SERVER_PORT", 8080)))

if not os.environ.get('SERVER_SOFTWARE','').startswith('Development'):
   # running publicly on GAE.
   try:
      from google.appengine.api import app_identity
      MS_HOSTPORT = app_identity.get_default_version_hostname()
      MS_PROTO = "https://"
   except:
      pass

MS_URL = MS_PROTO + MS_HOSTPORT

# security
OBJECT_KEY_SIZE = 4096

# gateways
GATEWAY_SESSION_SALT_LENGTH = 256
GATEWAY_SESSION_PASSWORD_LENGTH = 16
GATEWAY_RSA_KEYSIZE = OBJECT_KEY_SIZE

# volumes
VOLUME_RSA_KEYSIZE = OBJECT_KEY_SIZE

# users
USER_RSA_KEYSIZE = OBJECT_KEY_SIZE

USER_VOLUME_OWN = 1
USER_VOLUME_READONLY = 2
USER_VOLUME_READWRITE = 4
USER_VOLUME_HOST = 8

# caps
GATEWAY_CAP_READ_DATA = ms_pb2.ms_gateway_cert.CAP_READ_DATA
GATEWAY_CAP_WRITE_DATA = ms_pb2.ms_gateway_cert.CAP_WRITE_DATA
GATEWAY_CAP_READ_METADATA = ms_pb2.ms_gateway_cert.CAP_READ_METADATA
GATEWAY_CAP_WRITE_METADATA = ms_pb2.ms_gateway_cert.CAP_WRITE_METADATA
GATEWAY_CAP_COORDINATE = ms_pb2.ms_gateway_cert.CAP_COORDINATE

GATEWAY_ID_ANON = 0xFFFFFFFFFFFFFFFF    # taken from libsyndicate.h

# JSON
JSON_AUTH_COOKIE_NAME = "SynAuth"
JSON_SYNDICATE_CALLING_CONVENTION_FLAG = "__syndicate_json_rpc_calling_convention"

# key constants
KEY_UNSET = "unset"
KEY_UNUSED = "unused"

# verification methods
AUTH_METHOD_PUBKEY = "VERIFY_PUBKEY"
# AUTH_METHOD_PASSWORD = "VERIFY_PASSWORD"
AUTH_METHOD_NONE = "VERIFY_NONE"

# activation properties
PASSWORD_HASH_ITERS = 10000
PASSWORD_SALT_LENGTH = 32

# rate-limiting 
RESOLVE_MAX_PAGE_SIZE = 10 
MAX_NUM_CONNECTIONS = 50 
MAX_BATCH_REQUEST_SIZE = 6
MAX_BATCH_ASYNC_REQUEST_SIZE = 100
MAX_TRANSFER_TIME = 300

# ports 
GATEWAY_DEFAULT_PORT = 31111

# RESOLVE_MAX_PAGE_SIZE = 3       # for testing

