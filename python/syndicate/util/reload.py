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

# cert graph reload operations 

import os
import sys
import errno
import random
import logging
import base64
import binascii
import json
import requests
import urlparse
import traceback

logging.basicConfig( format='[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' )
log = logging.getLogger()
log.setLevel( logging.INFO )

# don't log request data
logging.getLogger("requests").setLevel(logging.CRITICAL)

import syndicate
import syndicate.util.certs as certs
import syndicate.util.crypto as crypto
import syndicate.util.objects as object_stub
import syndicate.util.client as rpc
import syndicate.util.storage as storage
import syndicate.util.gateway as gateway
import syndicate.protobufs.ms_pb2 as ms_pb2
import syndicate.protobufs.sg_pb2 as sg_pb2

from syndicate.util.objects import MissingKeyException, MissingCertException, CertExistsException 

import syndicate.syndicate as libsyndicate

from Crypto.Hash import SHA256 as HashAlg
from Crypto.PublicKey import RSA as CryptoKey
from Crypto import Random
from Crypto.Signature import PKCS1_PSS as CryptoSigner


#-------------------------------
def list_volume_writers( config, volume_id ):
    """
    Find all the gateways for a given volume that can write data or metadata
    """
    gateway_cert_paths = certs.list_gateway_cert_paths( config )
    ret = []

    for path in gateway_cert_paths:
       
        gateway_cert = None 

        try:
            with open(path, "r") as f:
                cert_bin = f.read()

            gateway_cert = ms_pb2.ms_gateway_cert()
            gateway_cert.ParseFromString( cert_bin )

        except Exception, e:
            log.exception(e)
            log.error("Failed to load '%s'" % path)
            return None

        if gateway_cert.volume_id != volume_id:
            continue

        if (gateway_cert.caps & (ms_pb2.ms_gateway_cert.CAP_WRITE_DATA | ms_pb2.ms_gateway_cert.CAP_WRITE_METADATA)) == 0:
            continue 

        log.debug("%s can write" % gateway_cert.name)
        ret.append( gateway_cert )

    return ret


#-------------------------------
def list_volume_coordinators( config, volume_id ):
    """
    Find all the gateways for a given volume that can coordinate writes
    """
    gateway_cert_paths = certs.list_gateway_cert_paths( config )
    ret = []

    for path in gateway_cert_paths:
       
        gateway_cert = None 

        try:
            with open(path, "r") as f:
                cert_bin = f.read()

            gateway_cert = ms_pb2.ms_gateway_cert()
            gateway_cert.ParseFromString( cert_bin )

        except Exception, e:
            log.exception(e)
            log.error("Failed to load '%s'" % path)
            return None

        if gateway_cert.volume_id != volume_id:
            continue

        if (gateway_cert.caps & (ms_pb2.ms_gateway_cert.CAP_COORDINATE)) == 0:
            continue 

        log.debug("%s can coordinate" % gateway_cert.name)
        ret.append( gateway_cert )

    return ret


#-------------------------------
def list_gateways_by_type( config, volume_id, gateway_type_str ):
    """
    Find all the gateways for a given volume with a particular type.
    The type should be a type alias, like "UG" or "RG" or "AG"
    Return the list of gateway certs on success.
    Raise on error
    """
    gateway_cert_paths = certs.list_gateway_cert_paths( config )
    ret = []
    
    type_aliases = object_stub.load_gateway_type_aliases( config )
    if type_aliases is None:
        raise Exception("Missing gateway type aliases")

    gateway_type = type_aliases.get(gateway_type_str, None)
    if gateway_type is None:
        raise ValueError("Unknown gateway type alias '%s'" % gateway_type_str )

    for path in gateway_cert_paths:
       
        gateway_cert = None 

        try:
            with open(path, "r") as f:
                cert_bin = f.read()

            gateway_cert = ms_pb2.ms_gateway_cert()
            gateway_cert.ParseFromString( cert_bin )

        except Exception, e:
            log.exception(e)
            log.error("Failed to load '%s'" % path)
            return None

        if gateway_cert.volume_id != volume_id:
            continue

        if gateway_cert.gateway_type != gateway_type:
            continue 

        log.debug("%s is type %s" % (gateway_cert.name, gateway_type))
        ret.append( gateway_cert )

    return ret


#-------------------------------
def make_reload_request( config, user_id, volume_id, gateway_id=None, gateway_name=None, cert_bundle_version=None, volume_version=None ):
    """
    Make a signed, serialized gateway-reload request.
    If gateway_id or gateway_name is not None, then the request will be destined to a particular gateway, and will be signed with the owner's private key.
    Otherwise, the request will be destined to all write/coordinate gateways in the volume, and will be signed with the volume owner's private key.
    Return the signed request.
    Raise on error.
    """

    signing_key = None
    gateway_cert_version = None

    # need either volume key or gateway key 
    if gateway_id is None and gateway_name is not None:
        gateway_id = object_stub.load_gateway_id( config, gateway_name )

    if gateway_name is None and gateway_id is not None:
        gateway_name = object_stub.load_gateway_name( config, gateway_id )

    if gateway_name is not None:
        # look up the gateway's cert--its version it must match gateway_cert_version
        gateway_cert = object_stub.load_gateway_cert( config, gateway_name )
        if gateway_cert is None:
            raise MissingCertException("Missing gateway certificate for %s" % gateway_name )

        assert volume_id == gateway_cert.volume_id, "Gateway '%s' is not in volume %s (but %s)" % (gateway_cert.name, volume_id, gateway_cert.volume_id)
        gateway_cert_version = gateway_cert.version
    
        # look up the owner's user 
        user_cert = object_stub.load_user_cert( config, str(gateway_cert.owner_id) )
        if user_cert is None:
            raise MissingCertException("Missing user certificate for %s, owner of '%s'" % (gateway_cert.owner_id, gateway_cert.name))

        # look up the user's private key, to sign with that 
        user_pkey = storage.load_private_key( config, "user", user_cert.email )
        if user_pkey is None:
            raise MissingCertException("Missing user private key for '%s'" % user_cert.email)

        log.debug("Sign reload request with private key of user '%s' for gateway '%s' in volume %s" % (user_cert.email, gateway_cert.name, volume_id))
        signing_key = user_pkey 

    else:
        # send to volume
        volume_cert = object_stub.load_volume_cert( config, str(volume_id) )
        if volume_cert is None:
            raise MissingCertException("Missing cert for volume %s" % (volume_id))

        owner_cert = object_stub.load_user_cert( config, str(volume_cert.owner_id) )
        if owner_cert is None:
            raise MissingCertException("Missing cert for user %s" % volume_cert.owner_id)

        volume_pkey = storage.load_private_key( config, "user", owner_cert.email )
        if volume_pkey is None:
            raise MissingKeyException("Missing both gateway and volume private keys")

        log.debug("Sign reload request with private key of volume owner '%s' in volume %s" % (owner_cert.email, volume_cert.name))
        signing_key = volume_pkey 

    if volume_version is None:
        # look up volume cert version 
        volume_cert = object_stub.load_volume_cert( config, str(volume_id) )
        if volume_cert is None:
            raise MissingCertException("Missing volume cert, and volume cert version is not given")

        volume_version = volume_cert.volume_version 

    if cert_bundle_version is None:
        # look up version vector; cross-check with volume version
        version_vector_txt = object_stub.load_object_file( config, "volume", str(volume_id) + ".bundle.version" )
        if version_vector_txt is None:
            raise MissingCertException("No cert bundle version information for volume '%s'" % volume_name)

        try:
            version_vector = json.loads(version_vector_txt)
        except:
            raise MissingCertException("Invalid version vector JSON")

        cert_bundle_version = version_vector.get('bundle_version', None)
        onfile_volume_version = version_vector.get('volume_version', None)

        assert cert_bundle_version is not None, "Missing bundle version in cert bundle version vector"
        assert onfile_volume_version is not None, "Missing volume version in cert bundle version vector"
        
        try:
            cert_bundle_version = int(cert_bundle_version)
            onfile_volume_version = int(onfile_volume_version)
        except:
            raise MissingCertException("Missing valid version information for cert bundle")

        assert onfile_volume_version == volume_version, "BUG: On-file cert bundle volume version (%s) does not match given volume version (%s)" % (onfile_volume_version, volume_version)
        

    req = sg_pb2.Request()
    
    req.request_type = sg_pb2.Request.RELOAD
    req.user_id = user_id
    req.volume_id = volume_id

    if gateway_id is not None:
        req.coordinator_id = gateway_id
    else:
        req.coordinator_id = 0

    req.src_gateway_id = libsyndicate.Syndicate.GATEWAY_TOOL
    req.message_nonce = random.randint(0, 2**64-1)

    req.volume_version = volume_version
    req.cert_version = cert_bundle_version
    req.file_id = 0             # ignored
    req.file_version = 0        # ignored
    req.fs_path = ""            # ignored

    if gateway_cert_version is not None:
        req.gateway_cert_version = gateway_cert_version

    # sign 
    req.signature = ""
    reqstr = req.SerializeToString()
    sig = crypto.sign_data( signing_key, reqstr )
    req.signature = base64.b64encode( sig )
    return req


#-------------------------------
def send_reload( config, user_id, volume_id, gateway_id ):
    """
    Generate and send a reload-request to a specific gateway.

    This method is used when updating an individual gateway (e.g. to change its driver, or host/port)

    Return 0 on success (HTTP 200)
    Return HTTP status code on error
    Return -1 on error
    """
    gateway_cert = object_stub.load_gateway_cert( config, str(gateway_id) )
    if gateway_cert is None:
        raise MissingCertException("Missing gateway cert for '%s'" % gateway_id )

    url = 'http://%s:%s' % (gateway_cert.host, gateway_cert.port)
    msg = make_reload_request( config, user_id, volume_id, gateway_id=gateway_id )
    msgtxt = msg.SerializeToString()
    try:
        req = requests.post( url, data={"control-plane": msgtxt} )
        if req.status_code == 200:
            return 0

        else:
            return req.status_code

    except (OSError, IOError), ioe:
        return -1

    except requests.exceptions.Timeout:
        log.debug("Timed out on %s" % gateway_id)
        return -1

    except requests.exceptions.RequestException, re:
        log.exception(re)
        return -1


#-------------------------------
def broadcast_reload( config, user_id, volume_id, cert_bundle_version=None, volume_version=None, gateway_names=None ):
    """
    Generate and broadcast a set of requests to all gateways that:
    * are write-capable
    * can receive writes
    * can coordinate writes.
    
    The message will have them synchronously reload their configurations.
    If gateway_names is given, then send to those gateways instead.
    Send it off and wait for their acknowledgements (or timeouts).

    This method is used when adding/removing gateways, and updating volume capability information.

    We'll need the volume private key.

    Return {"gateway_name": True|False|None} on success
        None indicates "unknown"
    """

    import grequests
    logging.getLogger("requests").setLevel(logging.CRITICAL)
    logging.getLogger("grequests").setLevel(logging.CRITICAL)

    gateway_certs = None 
    gateway_status = {}

    # sanity check--volume key is on file 
    volume_cert = object_stub.load_volume_cert( config, str(volume_id) )
    if volume_cert is None:
        raise MissingCertException("No volume cert for '%s'" % str(volume_id))

    owner_cert = object_stub.load_user_cert( config, str(volume_cert.owner_id))
    if owner_cert is None:
        raise MissingCertException("Missing user cert for %s, owner of volume '%s'" % (volume_cert.owner_id, volume_cert.name))

    volume_pkey = storage.load_private_key( config, "user", owner_cert.email )
    if volume_pkey is None:
        raise MissingKeyException("No volume key for owner '%s' of '%s'" % (owner_cert.email, volume_cert.name ))

    if gateway_names is None:
        writer_certs = list_volume_writers( config, volume_id )
        coord_certs = list_volume_coordinators( config, volume_id )
        recver_certs = list_gateways_by_type( config, volume_id, "RG" ) 
        gateway_certs = writer_certs + coord_certs + recver_certs

    else:
        gateway_certs = []
        for gateway_name in gateway_names:
            gateway_cert = object_stub.load_gateway_cert( config, gateway_name )
            if gateway_cert is None:
                raise MissingCertException("No gateway cert for '%s'" % gateway_name )

            gateway_certs.append( gateway_cert )

    for gateway_cert in gateway_certs:
        gateway_status[gateway_cert.name] = None

    gateway_url_names = dict( [('http://%s:%s' % (cert.host, cert.port), cert.name) for cert in gateway_certs] )
    urls = gateway_url_names.keys()

    msg = make_reload_request( config, user_id, volume_id, cert_bundle_version=cert_bundle_version, volume_version=volume_version )
    if msg is None:
        raise Exception("BUG: failed to generate config-reload request")

    def req_exception(request, exception):
        log.info("Caught exception on broadcast to '%s'" % request.url)
        log.info( traceback.format_exception(type(exception), exception, None) )
        gateway_name = gateway_url_names[request.url]
        gateway_status[gateway_name] = False

    msg_txt = msg.SerializeToString()
    reqs = [grequests.post(url, data={"control-plane": msg_txt}) for url in urls]

    # send all!
    iresps = grequests.imap( reqs, exception_handler=req_exception ) 
    for resp in iresps:
        url = resp.url
        purl = urlparse.urlparse(url)
        hostname = purl.hostname
        port = purl.port

        gateway_name = gateway_url_names.get('http://%s:%s' % (hostname,port), None)
        if gateway_name is None:
            log.warn("Unknown URL '%s'" % url)
            
        if resp.status_code == 200:
            gateway_status[gateway_name] = True
        else:
            gateway_status[gateway_name] = False
            log.warn("HTTP %s on broadcast to '%s'" % (resp.status_code, gateway_name))

    return gateway_status

