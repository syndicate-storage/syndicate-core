/*
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
*/

/**
 * @file libsyndicate/ms/volume.cpp
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief MS specific volume related functions
 *
 * @see libsyndicate/ms/volume.h
 */

#include "libsyndicate/ms/volume.h"
#include "libsyndicate/ms/url.h"

/// Free a volume
void ms_client_volume_free( struct ms_volume* vol ) {
   if( vol == NULL ) {
      return;
   }
   
   if( vol->volume_public_key != NULL ) {
      EVP_PKEY_free( vol->volume_public_key );
      vol->volume_public_key = NULL;
   }
   
   if( vol->volume_md != NULL ) {
      SG_safe_delete( vol->volume_md );
      vol->volume_md = NULL;
   }
   
   SG_safe_free( vol->name );
   
   memset( vol, 0, sizeof(struct ms_volume) );
}

/**
 * @brief Populate a Volume structure with the volume metadata.
 *
 * If this fails, the volume should be unaffected
 * @note the cert should already have been verified and validated
 * @note vol takes ownership of volume_cert
 * @retval 0 Success 
 * @retval -ENODATA if we can't load the volume public key 
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL if we can't verify the volume metadata
 */
int ms_client_volume_init( struct ms_volume* vol, ms::ms_volume_metadata* volume_cert ) {

   int rc = 0;
   char* new_name = NULL;
   EVP_PKEY* volume_pubkey = NULL;
   
   rc = md_load_pubkey( &volume_pubkey, volume_cert->volume_public_key().c_str(), volume_cert->volume_public_key().size() );
   if( rc != 0 ) {
      
      SG_error("md_load_pubkey rc = %d\n", rc );
      return rc;
   }
   
   new_name = SG_strdup_or_null( volume_cert->name().c_str() );
   if( new_name == NULL ) {
      return -ENOMEM;
   }
   
   else {
      // make all changes take effect
      vol->volume_id = volume_cert->volume_id();
      vol->volume_owner_id = volume_cert->owner_id();
      vol->blocksize = volume_cert->blocksize();
      vol->volume_version = volume_cert->volume_version();
      vol->volume_public_key = volume_pubkey;
      vol->name = new_name;  
      vol->volume_md = volume_cert;
   }
   
   return 0;
}
