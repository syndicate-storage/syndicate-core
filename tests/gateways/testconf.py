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

SYNDICATE_ADMIN="jcnelson@cs.princeton.edu"
SYNDICATE_MS="http://localhost:8080"

# I usually symlink the following paths into the current directory.
# TODO: the driver sandboxes still need to be installed to /usr/local/lib.  Fix this.
SYNDICATE_MS_ROOT="./ms_root/"
SYNDICATE_RG_ROOT="./rg_bin/"
SYNDICATE_UG_ROOT="./ug_bin/"
SYNDICATE_AG_ROOT="./ag_bin/"
SYNDICATE_PYTHON_ROOT="./python/"
SYNDICATE_TOOL="./syndicate"

SYNDICATE_MS_KEYDIR="./ms_src"
SYNDICATE_PRIVKEY_PATH=os.path.join(SYNDICATE_MS_KEYDIR, "admin.pem")
