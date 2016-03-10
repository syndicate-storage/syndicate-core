#!/usr/bin/python

"""
   Copyright 2014 The Trustees of Princeton University

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


import storage.storagetypes as storagetypes

import os
import base64
import urllib
import uuid
import json
from Crypto.Hash import SHA256 as HashAlg
from Crypto.PublicKey import RSA as CryptoKey
from Crypto import Random
from Crypto.Signature import PKCS1_PSS as CryptoSigner

import types
import errno
import time
import datetime
import random
import logging
import string
import traceback

from common.msconfig import *

class ClosureNameHolder( storagetypes.Object ):
   '''
   Mark a closure's name as in use
   '''
   
   name = storagetypes.String()
   closure_id = storagetypes.Integer()
   
   required_attrs = [
      "name"
   ]
   
   
   @classmethod
   def make_key_name( cls, name ):
      return "ClosureNameHolder: name=%s" % (name)
   
   @classmethod
   def create_async( cls,  _name, _id ):
      return ClosureNameHolder.get_or_insert_async( ClosureNameHolder.make_key_name( _name ), name=_name, closure_id=_id )
      
      

class Closure( storagetypes.Object ):
   
   closure_id = storagetypes.Integer(default=0)         # unique ID of this closure 
   name = storagetypes.String(default="")               # name of this closure
   owner_id = storagetypes.Integer(default=0)           # owner of this closure
   public = storagetypes.Boolean(default=False)         # whether or not other users' gateways can access this closure
   
   blob_ref = storagetypes.Text()                       # reference to the closure blob 
   
   # for RPC
   key_type = "closure"
   
   required_attrs = [
      "owner_id",
      "public",
      "blob_ref"
   ]
   
   read_attrs_api_required = [
      "blob_ref"
   ]
   
   read_attrs = [
      "closure_id",
      "name",
      "public"
   ] + read_attrs_api_required
   
   
   write_attrs = [
      "blob_ref"
   ]
   
   write_attrs_api_required = write_attrs
   
   key_attrs = [
      "closure_id"
   ]
   
   
   @classmethod
   def Create( cls, user, **kwargs ):
      """
      Create a closure.
      Only do this after the closure binary has been uploaded successfully.
      """
      
      # enforce ownership--make sure the calling user owns this closure
      kwargs['owner_id'] = user.owner_id

      # populate kwargs with default values for missing attrs
      cls.fill_defaults( kwargs )
      
      # sanity check: do we have everything we need?
      missing = cls.find_missing_attrs( kwargs )
      if len(missing) != 0:
         raise Exception( "Missing attributes: %s" % (", ".join( missing )))

      # sanity check: are our fields valid?
      invalid = cls.validate_fields( kwargs )
      if len(invalid) != 0:
         raise Exception( "Invalid values for fields: %s" % (", ".join( invalid )) )
      
      # ID...
      closure_id = random.randint( 0, 2**63 - 1 )
      kwargs['closure_id'] = closure_id
      
      closure_key_name = Closure.make_key_name( closure_id=closure_id )
      closure_key = storagetypes.make_key( cls, closure_key_name )
      
      # create a nameholder and this closure at once---there's a good chance we'll succeed
      closure_nameholder_fut = ClosureNameHolder.create_async( kwargs['name'], closure_id )
      closure_fut = cls.get_or_insert_async( closure_key_name, **kwargs )
      
      # wait for operations to complete
      storagetypes.wait_futures( [closure_nameholder_fut, closure_fut] )
      
      # check for collision...
      closure_nameholder = closure_nameholder_fut.get_result()
      closure = closure_fut.get_result()
      
      if closure_nameholder.closure_id != closure_id:
         # name collision...
         storagetypes.deferred.defer( Closure.delete_all, [closure_key] )
         raise Exception( "Closure '%s' already exists!" % kwargs['name'] )
      
      if closure.closure_id != closure_id:
         # ID collision...
         storagetypes.deferred.defer( Closure.delete_all, [closure_nameholder.key, closure_key] )
         raise Exception( "Closure ID collision.  Please try again." )
      
      # we're good!
      return closure_key

   
   @classmethod
   def Read( cls, closure_name_or_id, async=False, use_memcache=True ):
      """
      Given a Closure name or ID, read its record.  Optionally cache it.
      """
      
      # id or name?
      closure_id = None
      closure_name = None
      
      try:
         closure_id = int( closure_name_or_id )
      except:
         closure_name = closure_name 
         return cls.Read_ByName( closure_name, async=async, use_memcache=use_memcache )
      
      key_name = Closure.make_key_name( closure_id=closure_id )

      closure = None
      
      if use_memcache:
         closure = storagetypes.memcache.get( key_name )
         
      if closure is None:
         c_key = storagetypes.make_key( cls, Closure.make_key_name( closure_id=closure_id ) )
         
         if async:
            c_fut = c_key.get_async( use_memcache=False )
            return c_fut
         
         else:
            closure = c_key.get( use_memcache=False )
            
         if closure is None:
            logging.error("Closure %s not found at all!" % closure_id)
            
         elif use_memcache:
            storagetypes.memcache.set( key_name, closure )

      elif async:
         closure = storagetypes.FutureWrapper( closure )
         
      return closure
   
   
   @classmethod
   def Read_ByName_name_cache_key( cls, closure_name ):
      cls_name_to_id_cache_key = "Read_ByName: Closure: %s" % closure_name
      return cls_name_to_id_cache_key
   
   @classmethod
   def Read_ByName( cls, closure_name, async=False, use_memcache=True ):
      """
      Given a closure name, look it up and optionally cache it.
      """
      
      cls_name_to_id_cache_key = None 
      
      if use_memcache:
         cls_name_to_id_cache_key = Closure.Read_ByName_name_cache_key( closure_name )
         closure_id = storagetypes.memcache.get( cls_name_to_id_cache_key )
         
         if closure_id != None and isinstance( closure_id, int ):
            return cls.Read( closure_id, async=async, use_memcache=use_memcache )
         
      
      # no dice
      if async:
         cls_fut = cls.ListAll( {"Closure.name ==": closure_name}, async=async )
         return storagetypes.FutureQueryWrapper( cls_fut )
      
      else:
         closure = cls.ListAll( {"Closure.name ==": closure_name}, async=async )
         
         if len(closure) > 1:
            raise Exception( "More than one Closure named '%s'" % (closure_name) )
         
         if closure is not None: 
            closure = closure[0]
         else:
            closure = None
         
         if use_memcache:
            if closure is not None:
               to_set = {
                  cls_name_to_id_cache_key: closure.closure_id,
                  Closure.make_key_name( closure_id=closure_id ): closure
               }
               
               storagetypes.memcache.set_multi( to_set )
            
         return closure

   @classmethod
   def FlushCache( cls, closure_id ):
      """
      Purge cached copies of this closure
      """
      closure_key_name = Closure.make_key_name( closure_id=closure_id )
      storagetypes.memcache.delete(closure_key_name)
      
      
   @classmethod 
   def Update( cls, cls_name_or_id, **fields ):
      """
      Update the closure--i.e. to refer to a new binary.
      NOTE: You should call Reversion() on all Gateways that use this closure after calling this method
      """
      
      # get closure ID
      try:
         cls_id = int(cls_name_or_id)
      except:
         closure = Closure.Read( cls_name_or_id )
         if closure:
            cls_id = closure.closure_id 
         else:
            raise Exception("No such Closure '%s'" % cls_name_or_id )
      
      if len(fields.keys()) == 0:
         return True
      
      # validate...
      invalid = cls.validate_fields( fields )
      if len(invalid) != 0:
         raise Exception( "Invalid values for fields: %s" % (", ".join( invalid )) )

      invalid = cls.validate_write( fields )
      if len(invalid) != 0:
         raise Exception( "Unwritable fields: %s" % (", ".join(invalid)) )
      
      
      def update_txn( fields ):
         '''
         Update the Closure transactionally.
         '''
         
         closure = cls.Read(cls_id)
         if closure is None:
            raise Exception("No Closure with the ID %d exists.", cls_id)
         
         
         # purge from cache
         Closure.FlushCache( cls_id )
         
         # apply update
         for (k,v) in fields.items():
            setattr( closure, k, v )
         
         return closure.put()
      
      
      closure_key = None
      try:
         closure_key = storagetypes.transaction( lambda: update_txn( fields ), xg=True )
         assert closure_key is not None, "Transaction failed"
      except Exception, e:
         logging.exception( e )
         raise e
         
      return True
   
   
   @classmethod 
   def Delete( cls, cls_name_or_id ):
      """
      Given a closure ID, delete the corresponding closure.
      NOTE: Make sure that no gateway references this closure first.
      """
      
      closure = Closure.Read( cls_name_or_id )
      if closure is not None:
         cls_id = closure.closure_id 
      else:
         raise Exception("No such Closure '%s'" % cls_name_or_id )
      
      key_name = Closure.make_key_name( closure_id=cls_id )

      cls_key = storagetypes.make_key( cls, key_name )
      cls_name_key = storagetypes.make_key( ClosureNameHolder, ClosureNameHolder.make_key_name( closure.name ) )
      
      cls_delete_fut = cls_key.delete_async()
      cls_name_delete_fut = cls_name_key.delete_async()
            
      Closure.FlushCache( cls_id )
      
      cls_name_to_id_cache_key = Closure.Read_ByName_name_cache_key( cls_name_or_id )
      storagetypes.memcache.delete( cls_name_to_id_cache_key )
      
      storagetypes.wait_futures( [cls_delete_fut, cls_name_delete_fut] )
      
      return True
