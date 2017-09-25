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
 * @file libsyndicate/ms/gateway.cpp
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief MS specific gateway related functions
 *
 * @see libsyndicate/ms/gateway.h
 */

#include "libsyndicate/ms/gateway.h"
#include "libsyndicate/ms/cert.h"
#include "libsyndicate/ms/volume.h"

/**
 * @brief Sign an outbound message from us (needed by libsyndicate python wrapper)
 * @retval 0 Success 
 * @retval -ENOMEM Out of Memory
 */
int ms_client_sign_gateway_message( struct ms_client* client, char const* data, size_t len, char** sigb64, size_t* sigb64_len ) {
    
    int rc = 0;
    ms_client_config_rlock( client );
    
    rc = md_sign_message( client->gateway_key, data, len, sigb64, sigb64_len );
    
    ms_client_config_unlock( client );
    
    return rc;
}

/**
 * @brief Verify that a message came from a peer with the given ID (needed by libsyndicate python wrapper)
 * @retval 0 Success
 * @retval -ENOENT The volume_id does not match our volume_id
 * @retval -EAGAIN No certificate could be found for this gateway
 */
int ms_client_verify_gateway_message( struct ms_client* client, uint64_t volume_id, uint64_t gateway_id, char const* msg, size_t msg_len, char* sigb64, size_t sigb64_len ) {
   
   ms_client_config_rlock( client );

   if( client->volume->volume_id != volume_id ) {
      // not from this volume
      SG_error("Message from outside the Volume (%" PRIu64 ")\n", volume_id );
      ms_client_config_unlock( client );
      return -ENOENT;
   }
   
   // only non-anonymous gateways can write
   ms_cert_bundle::iterator itr = client->certs->find( gateway_id );
   if( itr == client->certs->end() ) {
      
      // not found here--probably means we need to reload our certs
      SG_warn("No cached certificate for Gateway %" PRIu64 "\n", gateway_id );
      
      sem_post( &client->config_sem );
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   int rc = md_verify_signature( itr->second->pubkey, msg, msg_len, sigb64, sigb64_len );
   
   ms_client_config_unlock( client );
   
   return rc;
}

/**
 * @brief Get the type of gateway, given an id 
 * @return The type
 * @retval SG_INVALID_GATEWAY_ID Error
 */
uint64_t ms_client_get_gateway_type( struct ms_client* client, uint64_t g_id ) {
   
   ms_client_config_rlock( client );
   
   uint64_t ret = SG_INVALID_GATEWAY_ID;
   
   ms_cert_bundle::iterator itr = client->certs->find( g_id );
   if( itr != client->certs->end() ) {
      
      ret = itr->second->gateway_type;
   }
   
   ms_client_config_unlock( client );
   return ret;
}


/**
 * @brief Get the name of the gateway
 * @retval 0 Success
 * @retval -ENOTCONN Are not connected to a volume
 * @retval -ENOMEM Out of Memory
 * @retval -EAGAIN The gateway is not known to us, but could be if we reloaded the config
 */
int ms_client_get_gateway_name( struct ms_client* client, uint64_t gateway_id, char** gateway_name ) {
   
   ms_client_config_rlock( client );
   
   int ret = 0;
   
   uint64_t gateway_type = ms_client_get_gateway_type( client, gateway_id );
   
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   // should return a non-null cert, since we know this gateway's type
   struct ms_gateway_cert* cert = ms_client_get_gateway_cert( client, gateway_id );
   
   if( cert != NULL ) {
      
      *gateway_name = SG_strdup_or_null( cert->name );
      if( *gateway_name == NULL ) {
         
         ret = -ENOMEM;
      }
   }
   else {
      
      ret = -ENOTCONN;
   }
   
   ms_client_config_unlock( client );
   return ret;
}

/**
 * @brief Get a gateway's host URL 
 * @return The calloc'ed URL
 * @retval NULL Error (i.e. gateway not known, is anonymous, or not found)
 */
char* ms_client_get_gateway_url( struct ms_client* client, uint64_t gateway_id ) {
   
   char* ret = NULL;
   
   ms_client_config_rlock( client );
   
   uint64_t gateway_type = ms_client_get_gateway_type( client, gateway_id );
   
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      
      ms_client_config_unlock( client );
      return NULL;
   }
   
   struct ms_gateway_cert* cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      ms_client_config_unlock( client );
      return NULL;
   }
   
   // found! 
   ret = SG_CALLOC( char, strlen("http://") + strlen(cert->hostname) + 1 + 7 + 1 );
   if( ret == NULL ) {
      
      ms_client_config_unlock( client );
      return NULL;
   }
   
   sprintf( ret, "http://%s:%d/", cert->hostname, cert->portnum );
   
   ms_client_config_unlock( client );
   
   return ret;
}

/**
 * @brief Check a gateway's capabilities (as a bit mask)
 * @retval 0 All the capabilites are allowed.
 * @retval -EINVAL Bad arguments
 * @retval -EPERM At least one is not.
 * @retval -EAGAIN The gateway is not known, and the caller should reload
 */
int ms_client_check_gateway_caps( struct ms_client* client, uint64_t gateway_id, uint64_t caps ) {
   
   struct ms_gateway_cert* cert = NULL;
   int ret = 0;
   
   uint64_t gateway_type = ms_client_get_gateway_type( client, gateway_id );
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      
      return -EINVAL;
   }
   
   ms_client_config_rlock( client );
   
   cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      // not found--need to reload certs?
      ms_client_config_unlock( client );
      
      return -EAGAIN;
   }
   
   ret = ((cert->caps & caps) == caps ? 0 : -EPERM);
   
   ms_client_config_unlock( client );
   
   return ret;
}


/**
 * @brief Get a gateway's user
 * @param[out] user_id The user ID
 * @retval 0 Success
 * @retval -EAGAIN The gateway is not known, and the caller should reload
 * @retval -EINVAL Bad arguments
 */
int ms_client_get_gateway_user( struct ms_client* client, uint64_t gateway_id, uint64_t* user_id ) {
   
   struct ms_gateway_cert* cert = NULL;
   
   ms_client_config_rlock( client );
   
   uint64_t gateway_type = ms_client_get_gateway_type( client, gateway_id );
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      // not found--need to reload certs?
      ms_client_config_unlock( client );
      
      return -EAGAIN;
   }
   
   *user_id = cert->user_id;
   
   ms_client_config_unlock( client );
   
   return 0;
}


/**
 * @brief Get a gateway's volume
 * @param[out] *volume_id The volumd ID
 * @retval 0 Success
 * @retval -EAGAIN The gateway is not known, and the caller should reload
 * @retval -EINVAL Bad arguments
 */
int ms_client_get_gateway_volume( struct ms_client* client, uint64_t gateway_id, uint64_t* volume_id ) {
   
   struct ms_gateway_cert* cert = NULL;
   
   ms_client_config_rlock( client );
   
   uint64_t gateway_type = ms_client_get_gateway_type( client, gateway_id );
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      // not found--need to reload certs?
      ms_client_config_unlock( client );
      
      return -EAGAIN;
   }
   
   *volume_id = cert->volume_id;
   
   ms_client_config_unlock( client );
   
   return 0;
}


/**
 * @brief Get the gateway's hash.
 *
 * @note hash_buf should be at least SHA256_DIGEST_LEN bytes long
 * @retval 0 Success
 * @retval -EAGAIN No certificate
 */
int ms_client_get_gateway_driver_hash( struct ms_client* client, uint64_t gateway_id, unsigned char* hash_buf ) {
   
   struct ms_gateway_cert* cert = NULL;
   
   ms_client_config_rlock( client );
   
   cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      // no cert 
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   memcpy( hash_buf, cert->driver_hash, cert->driver_hash_len );
   
   ms_client_config_unlock( client );
   
   return 0;
}


/**
 * @brief Get a copy of the gateway's driver text.
 * @retval 0 Success 
 * @retval -EAGAIN cert is not on file, or there is (currently) no driver 
 * @retval -ENOMEM Out of Memory
 */
int ms_client_gateway_get_driver_text( struct ms_client* client, char** driver_text, size_t* driver_text_len ) {
   
   struct ms_gateway_cert* cert = NULL;
   
   ms_client_config_rlock( client );
   
   cert = ms_client_get_gateway_cert( client, client->gateway_id );
   if( cert == NULL ) {
      
      // no cert for us
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   if( cert->driver_text == NULL ) {
      
      // no driver 
      ms_client_config_unlock( client );
      return -EAGAIN;
   }
   
   *driver_text = SG_CALLOC( char, cert->driver_text_len );
   if( *driver_text == NULL ) {
      
      // OOM 
      ms_client_config_unlock( client );
      return -ENOMEM;
   }
   
   memcpy( *driver_text, cert->driver_text, cert->driver_text_len );
   *driver_text_len = cert->driver_text_len; 
   ms_client_config_unlock( client );
   
   return 0;
}


/**
 * @brief Get my private key as a PEM-encoded string
 * @param[out] buf The PEM-encoded key
 * @param[out] len The length of buf
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -ENODATA No public key
 */
int ms_client_gateway_key_pem( struct ms_client* client, char** buf, size_t* len ) {
   
   int rc = 0;
   char* ret = NULL;
   
   ms_client_rlock( client );
   
   if( client->gateway_key_pem != NULL ) {
      
      ret = SG_strdup_or_null( client->gateway_key_pem );
      
      if( ret == NULL ) {
         rc = -ENOMEM;
      }
      else {
         *buf = ret;
         *len = strlen(ret);
      }
   }
   else {
      rc = -ENODATA;
   }
   
   ms_client_unlock( client );
   return rc;
}
