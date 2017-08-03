#!/usr/bin/env python

"""
   Copyright 2013-2017 The Trustees of Princeton University

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


# Include the Dropbox SDK
import dropbox
import os
import errno
import logging

import syndicate.util.gateway as gateway

log = logging.getLogger()
formatter = logging.Formatter('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s')
handler_stream = logging.StreamHandler()
handler_stream.setFormatter(formatter)
log.addHandler(handler_stream)


#-------------------------
def connect_dropbox(secrets):
    """
    Connect to dropbox
    """
    dbx_key = secrets.get('DROPBOX_TOKEN', None)
    assert dbx_key, "No DROPBOX_TOKEN given in secrets"

    dbx = dropbox.Dropbox(dbx_key)
    return dbx

#-------------------------
def write_chunk(chunk_request, chunk_buf, config, secrets):
    """
    Write a chunk to dropbox.
    Return 0 on success
    Return -EREMOTEIO on failure
    """
    chunk_path = gateway.request_to_storage_path(chunk_request)

    # canonicalize 
    chunk_name = '/' + chunk_path.replace('/', r'-x2f')

    dbx = connect_dropbox(secrets)
    buf = str(chunk_buf)

    try:
        file_info = dbx.files_upload(chunk_buf, chunk_name, mode=dropbox.files.WriteMode('overwrite'))
        return 0
    except Exception as e:
        log.exception(e)
        log.error("Failed to write chunk %s" % chunk_name)
        rc = -errno.EREMOTEIO

    return rc


#-------------------------
def read_chunk(chunk_request, outfile, config, secrets):
    """
    Read a chunk from dropbox
    Return 0 on success
    Return -EREMOTEIO on failrue
    """
    chunk_path = gateway.request_to_storage_path(chunk_request)

    # canonicalize
    chunk_name = '/' + chunk_path.replace('/', r'-x2f')

    dbx = connect_dropbox(secrets)
    
    try:
        metadata, req = dbx.files_download(chunk_name)
        if req.status_code != 200:
            log.debug("Failed to download %s (status code %s)" % (chunk_name, req.status_code))
            return -errno.EREMOTEIO

        outfile.write(str(req.text))
    except Exception as e:
        log.exception(e)
        log.error("Failed to read chunk %s" % chunk_name)
        return -errno.EREMOTEIO

    return 0
    

#-------------------------
def delete_chunk(chunk_request, config, secrets):
    """
    Delete a chunk from dropbox
    Return 0 on success
    Return -EREMOTEIO on failure
    """
    chunk_path = gateway.request_to_storage_path(chunk_request)

    # canonicalize
    chunk_name = '/' + chunk_path.replace('/', r'-x2f')

    dbx = connect_dropbox(secrets)

    try:
        dbx.files_delete(chunk_name)
    except Exception as e:
        log.exception(e)
        log.error("Failed to delete chunk %s" % chunk_name)
        return -errno.EREMOTEIO

    return 0


if __name__ == "__main__":
    import sys
    import StringIO
    from syndicate.protobufs.sg_pb2 import DriverRequest

    dbx_key = sys.argv[1]
    secrets = {'DROPBOX_TOKEN': dbx_key}

    req = DriverRequest()
    req.volume_id = 123
    req.user_id = 456
    req.coordinator_id = 789
    req.file_id = 0xabcd
    req.file_version = 1
    req.request_type = DriverRequest.BLOCK
    req.path = '/foo/bar'

    sio = StringIO.StringIO()

    print "write chunk"
    res = write_chunk(req, "hello world", {}, secrets)
    assert res == 0, res

    print "read chunk"
    res = read_chunk(req, sio, {}, secrets)
    assert res == 0, res

    print "delete chunk"
    res = delete_chunk(req, {}, secrets)
    assert res == 0, res
