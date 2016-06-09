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

ENV_DEFAULTS = {
    "SYNDICATE_ADMIN": "jcnelson@cs.princeton.edu",
    "SYNDICATE_MS": "http://localhost:8080",
    "SYNDICATE_MS_ROOT": "./ms_root/",
    "SYNDICATE_RG_ROOT": "/usr/local/bin/",
    "SYNDICATE_UG_ROOT": "/usr/local/bin/",
    "SYNDICATE_AG_ROOT": "/usr/local/bin/",
    "SYNDICATE_PYTHON_ROOT": "/usr/local/lib/python2.7/dist-packages/",
    "SYNDICATE_TOOL": "/usr/local/bin/syndicate",
    "SYNDICATE_MS_KEYDIR": "./ms_src",
    "SYNDICATE_PRIVKEY_PATH": "./ms_src/admin.pem"
}

for envar in ENV_DEFAULTS.keys():
    if os.environ.get(envar, None) is not None:
        ENV_DEFAULTS[envar] = os.environ[envar]

# export as module variables
for envar in ENV_DEFAULTS.keys():
    globals()[envar] = ENV_DEFAULTS[envar]
    print "$ export %s=\"%s\"" % (envar, ENV_DEFAULTS[envar])

