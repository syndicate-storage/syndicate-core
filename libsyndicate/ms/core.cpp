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
 * @file libsyndicate/ms/core.cpp
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief MS specific core syndicate functions
 *
 * @see libsyndicate/ms/core.h
 */

#include "libsyndicate/ms/core.h"
#include "libsyndicate/ms/benchmark.h"
#include "libsyndicate/ms/cert.h"
#include "libsyndicate/ms/file.h"
#include "libsyndicate/ms/volume.h"
#include "libsyndicate/ms/path.h"
#include "libsyndicate/ms/getattr.h"
#include "libsyndicate/ms/volume.h"

/**
 * @brief Verify that a given key has our desired security parameters
 * @retval 0 Success
 * @retval -EINVAL Not an RSA key or invalid RSA size
 */
int ms_client_verify_key( EVP_PKEY* key ) {
   
   RSA* ref_rsa = EVP_PKEY_get1_RSA( key );
   int size = 0;
   
   if( ref_rsa == NULL ) {
      // not an RSA key
      SG_error("Not an RSA key: %p\n", key);
      return -EINVAL;
   }

   size = RSA_size( ref_rsa );
   if( size * 8 != SG_RSA_KEY_SIZE ) {
      
      // not the right size
      SG_error("Invalid RSA size %d\n", size * 8 );
      return -EINVAL;
   }
   return 0;
}


/**
 * @brief Set up secure CURL handle 
 * @note The caller must set the CURLOPT_USERPWD field
 * @return 0
 */
int ms_client_init_curl_handle( struct ms_client* client, CURL* curl, char const* url, char const* auth_header ) {
   
   md_init_curl_handle( client->conf, curl, url, client->conf->connect_timeout);
   curl_easy_setopt( curl, CURLOPT_USE_SSL, 1L );
   curl_easy_setopt( curl, CURLOPT_SSL_VERIFYPEER, (client->conf->verify_peer ? 1L : 0L) );
   curl_easy_setopt( curl, CURLOPT_SSL_VERIFYHOST, 2L );
   curl_easy_setopt( curl, CURLOPT_NOSIGNAL, 1L );
   curl_easy_setopt( curl, CURLOPT_SSL_CIPHER_LIST, MS_CIPHER_SUITES );
   
   curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1L );
   curl_easy_setopt( curl, CURLOPT_MAXREDIRS, 10L );
   curl_easy_setopt( curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC );
   
   curl_easy_setopt( curl, CURLOPT_TIMEOUT, client->ms_transfer_timeout );
   
   if( auth_header != NULL ) {
      curl_easy_setopt( curl, CURLOPT_USERPWD, auth_header );
   }

   return 0;
}


/**
 * @brief Load up a key
 *
 * Storing its OpenSSL EVP_PKEY form and optionally a duplicate of its PEM-encoded value (if key_pem_dup is not NULL)
 * @retval 0 Success 
 * @retval !0 Error
 */
int ms_client_try_load_key( struct md_syndicate_conf* conf, EVP_PKEY** key, char** key_pem_dup, char const* key_pem, bool is_public ) {
   
   int rc = 0;
   char const* method = NULL;
   
   if( key_pem != NULL ) {
      
      // we were given a key.  Load it
      if( is_public ) {
         rc = md_load_pubkey( key, key_pem, strlen(key_pem) );
         method = "md_load_pubkey";
      }
      else {
         rc = md_load_privkey( key, key_pem, strlen(key_pem) );
         method = "md_load_privkey";
      }
      
      if( rc != 0 ) {
         SG_error("%s rc = %d\n", method, rc );
         return rc;
      }
      
      rc = ms_client_verify_key( *key );
      if( rc != 0 ) {
         SG_error("ms_client_verify_key rc = %d\n", rc );
         return rc;
      }

      // hold onto the PEM form.
      // if private, mlock it
      if( key_pem_dup ) {
         
         struct mlock_buf pkey_buf;
         memset( &pkey_buf, 0, sizeof(pkey_buf) );
         
         rc = mlock_dup( &pkey_buf, key_pem, strlen(key_pem) + 1 );
         if( rc != 0 ) {
            
            SG_error("mlock_dup rc = %d\n", rc );
            return rc;
         }
         
         *key_pem_dup = (char*)pkey_buf.ptr;
      }
   }
   
   return 0;
}
   

/**
 * @brief Create an MS client context
 *
 * It takes ownership of volume_cert and syndicate_pubkey
 * @retval 0 Success 
 * @retval -EINVAL if config is NULL 
 * @retval -ENOMEM Out of Memory
 */
int ms_client_init( struct ms_client* client, struct md_syndicate_conf* conf, EVP_PKEY* syndicate_pubkey, ms::ms_volume_metadata* volume_cert ) {

   int rc = 0;
   struct ms_volume* volume = NULL;
   
   if( conf == NULL ) {
      return -EINVAL;
   }
   
   memset( client, 0, sizeof(struct ms_client) );
   
   rc = pthread_rwlock_init( &client->lock, NULL );
   if( rc != 0 ) {
      return -rc;
   }
   
   rc = pthread_rwlock_init( &client->config_lock, NULL );
   if( rc != 0 ) {
      
      pthread_rwlock_destroy( &client->lock );
      return rc;
   }
   
   sem_init( &client->config_sem, 0, 0 );
   
   // get MS url 
   client->url = SG_strdup_or_null( conf->metadata_url );
   if( client->url == NULL ) {
      pthread_rwlock_destroy( &client->lock );
      sem_destroy( &client->config_sem );
      return -ENOMEM;
   }
   
   // set up downloader for MS API calls 
   client->dl = md_downloader_new();
   if( client->dl == NULL ) {

      SG_safe_free( client->url );
      sem_destroy( &client->config_sem );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      return -ENOMEM;
   }

   rc = md_downloader_init( client->dl, "ms-client" );
   if( rc != 0 ) {
      
      SG_error("md_downloader_start rc = %d\n", rc );
     
      SG_safe_free( client->dl ); 
      SG_safe_free( client->url );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      sem_destroy( &client->config_sem );
      
      return rc;
   }
   
   client->gateway_type = conf->gateway_type;
   
   // clear the / at the end...
   if( strrchr( client->url, '/' ) != NULL ) {
      
      md_strrstrip( client->url, "/" );
   }
   
   // new volume 
   volume = SG_CALLOC( struct ms_volume, 1 );
   if( volume == NULL ) {
     
      md_downloader_shutdown( client->dl ); 
      SG_safe_free( client->dl );
      SG_safe_free( client->url );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      sem_destroy( &client->config_sem );
      return -ENOMEM;
   }
    
   // load the Volume information, using the new client keys
   rc = ms_client_volume_init( volume, volume_cert );
   if( rc != 0 ) {
      
      SG_error("ms_client_volume_init('%s') rc = %d\n", conf->volume_name, rc );
      md_downloader_shutdown( client->dl ); 
      SG_safe_free( client->dl );
      SG_safe_free( client->url );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      sem_destroy( &client->config_sem );
      SG_safe_free( volume );
      return rc;
   }
   
   client->conf = conf;
   client->owner_id = conf->owner;
   client->gateway_id = conf->gateway;
   client->portnum = conf->portnum;
   client->volume = volume;
   
   client->page_size = MS_CLIENT_DEFAULT_RESOLVE_PAGE_SIZE;
   client->max_request_batch = MS_CLIENT_DEFAULT_MAX_REQUEST_BATCH;
   client->max_request_async_batch = MS_CLIENT_DEFAULT_MAX_ASYNC_REQUEST_BATCH;
   client->max_connections = MS_CLIENT_DEFAULT_MAX_CONNECTIONS;
   client->ms_transfer_timeout = MS_CLIENT_DEFAULT_MS_TRANSFER_TIMEOUT;
   
   // cert bundle 
   client->certs = SG_safe_new( ms_cert_bundle() );
   if( client->certs == NULL ) {
      
      md_downloader_shutdown( client->dl ); 
      SG_safe_free( client->dl );
      SG_safe_free( client->url );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      ms_client_volume_free( client->volume );
      sem_destroy( &client->config_sem );
      
      return -ENOMEM;
   }
   
   // obtain gateway private key, if we have it 
   if( conf->gateway_key != NULL ) {
            
        rc = ms_client_try_load_key( conf, &client->gateway_key, &client->gateway_key_pem, conf->gateway_key, false );
        if( rc != 0 ) {
            SG_error("ms_client_try_load_key rc = %d\n", rc );
            
            md_downloader_shutdown( client->dl ); 
            SG_safe_free( client->dl );
            SG_safe_free( client->url );
            pthread_rwlock_destroy( &client->config_lock );
            pthread_rwlock_destroy( &client->lock );
            ms_client_volume_free( client->volume );
            sem_destroy( &client->config_sem );
            
            return rc;
        }

        // derive the public key from it
        rc = md_public_key_from_private_key( &client->gateway_pubkey, client->gateway_key );

        if( rc != 0 || client->gateway_pubkey == NULL ) {
            
            SG_error("md_public_key_from_private_key( %p ) rc = %d\n", client->gateway_key, rc );
            
            md_downloader_shutdown( client->dl ); 
            SG_safe_free( client->dl );
            SG_safe_free( client->url );
            pthread_rwlock_destroy( &client->config_lock );
            pthread_rwlock_destroy( &client->lock );
            ms_client_volume_free( client->volume );
            sem_destroy( &client->config_sem );
            
            // NOTE: was mlock'ed
            munlock( client->gateway_key_pem, client->gateway_key_pem_len );
            SG_safe_free( client->gateway_key_pem );
            
            EVP_PKEY_free( client->gateway_key );
            
            return rc;
        }
   }
   else {
       
        client->gateway_key = NULL;
        client->gateway_pubkey = NULL;
   }
   
   // NOTE: ms_client_try_load_key will mlock a private key 
   client->gateway_key_pem_mlocked = true;
   
   // start downloading
   rc = md_downloader_start( client->dl );
   if( rc != 0 ) {
      
      SG_error("Failed to start downloader, rc = %d\n", rc );
      
      md_downloader_shutdown( client->dl ); 
      SG_safe_free( client->dl );
      SG_safe_free( client->url );
      pthread_rwlock_destroy( &client->config_lock );
      pthread_rwlock_destroy( &client->lock );
      ms_client_volume_free( client->volume );
      sem_destroy( &client->config_sem );
      
      // NOTE: was mlock'ed
      munlock( client->gateway_key_pem, client->gateway_key_pem_len );
      SG_safe_free( client->gateway_key_pem );
      
      if( client->gateway_key != NULL ) {
         EVP_PKEY_free( client->gateway_key );
      }
      
      if( client->gateway_pubkey != NULL ) {
         EVP_PKEY_free( client->gateway_pubkey );
      }
      
      return rc;
   }
   
   client->syndicate_pubkey = syndicate_pubkey;
   client->inited = true;               // safe to destroy later
   
   return rc;
}


/**
 * @brief Destroy an MS client context 
 * @note Always succeeds
 */
int ms_client_destroy( struct ms_client* client ) {
   
   if( client == NULL ) {
      SG_warn("client is %p\n", client);
      return 0;
   }
   
   if( !client->inited ) {
      SG_warn("client->inited = %d\n", client->inited );
      return 0;
   }
   
   ms_client_wlock( client );
   
   client->inited = false;
   
   md_downloader_stop( client->dl );
   
   // clean up config
   ms_client_config_wlock( client );

   if( client->volume != NULL ) {
      ms_client_volume_free( client->volume );
      SG_safe_free( client->volume );
   }
   
   if( client->certs != NULL ) {
      ms_client_cert_bundle_free( client->certs );
      SG_safe_delete( client->certs );
   }
   
   ms_client_config_unlock( client );
   pthread_rwlock_destroy( &client->config_lock );
   
   // clean up our state
   SG_safe_free( client->url );
   
   if( client->gateway_key ) {
      
      EVP_PKEY_free( client->gateway_key );
      client->gateway_key = NULL;
   }
   
   if( client->gateway_pubkey != NULL ) {
      
      EVP_PKEY_free( client->gateway_pubkey );
      client->gateway_pubkey = NULL;
   }
   
   if( client->gateway_key_pem != NULL ) {
      
      // NOTE: was mlock'ed
      if( client->gateway_key_pem_mlocked ) {
         munlock( client->gateway_key_pem, client->gateway_key_pem_len );
      }
      SG_safe_free( client->gateway_key_pem );
   }
   
   if( client->syndicate_pubkey != NULL ) {
       
      EVP_PKEY_free( client->syndicate_pubkey );
      client->syndicate_pubkey = NULL;
   }
   
   md_downloader_shutdown( client->dl );
   SG_safe_free( client->dl );
   
   ms_client_unlock( client );
   pthread_rwlock_destroy( &client->lock );
 
   SG_info("%s", "MS client shutdown\n");
   
   return 0;
}


/**
 * @brief Generate an authentication header, e.g. for the CURLOPT_USERPWD field.
 *
 * format: "${g_type}_${g_id}:${signature}"
 * signature input: "${g_type}_${g_id}:${url}"
 * @param[out] auth_header Allocate a null-terminated string
 * @retval 0 Success
 * @retval -EPERM Signature generation error
 * @retval -ENOMEM Out of Memory
 */
int ms_client_auth_header( struct ms_client* client, char const* url, char** auth_header ) {
   
   int rc = 0;
   
   char* message = NULL;
   size_t message_len = 0;
   
   char* sigb64 = NULL;
   size_t sigb64_len = 0;
   
   char* ret = NULL;
   size_t ret_len = 0;
   
   // no key? no auth header 
   if( client->gateway_key == NULL ) {
       *auth_header = NULL;
       return 0;
   }
   
   ms_client_rlock( client );
   
   uint64_t gateway_type = client->gateway_type;
   uint64_t gateway_id = client->gateway_id;
   
   ms_client_unlock( client );
   
   message_len = 50 + 1 + 50 + 1 + strlen(url) + 2;
   message = SG_CALLOC( char, message_len );
   if( message == NULL ) {
      
      return -ENOMEM;
   }
   
   snprintf( message, message_len - 1, "%" PRIu64 "_%" PRIu64 ":%s", gateway_type, gateway_id, url );
   
   rc = md_sign_message( client->gateway_key, message, strlen( message ), &sigb64, &sigb64_len );
   SG_safe_free( message );
   
   if( rc != 0 ) {
      
      if( rc != -ENOMEM ) {
         
         SG_error("md_sign_message rc = %d\n", rc );
         return -EPERM;
      }
      else {
         return rc;
      }
   }
   
   ret_len = 50 + 1 + 50 + 1 + sigb64_len + 2;
   ret = SG_CALLOC( char, ret_len );
   if( ret == NULL ) {
      
      SG_safe_free( sigb64 );
      return -ENOMEM;
   }
   
   snprintf( ret, ret_len - 1, "%" PRIu64 "_%" PRIu64 ":%s", gateway_type, gateway_id, sigb64 );
   SG_safe_free( sigb64 );
   
   *auth_header = ret;
   return 0;
}

/**
 * @brief Synchronously download metadata from the MS.
 *
 * Logs benchmark data.
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 * @retval -ETIMEDOUT The tranfser could not complete in time 
 * @retval -EAGAIN Signaled to retry the request 
 * @retval -EREMOTEIO The HTTP error is >= 500 
 * @retval -EPROTO The HTTP error was between 400 and 499
 * @retval Other -errno on socket- and recv-related errors
 */
int ms_client_download( struct ms_client* client, char const* url, char** buf, off_t* buflen ) {
   
   int rc = 0;
   CURL* curl = NULL;
   struct ms_client_timing timing;
   char* auth_header = NULL;
   
   memset( &timing, 0, sizeof(struct ms_client_timing) );
   
   curl = curl_easy_init();  
   if( curl == NULL ) {
      return -ENOMEM;
   }
   
   // generate auth header
   rc = ms_client_auth_header( client, url, &auth_header );
   if( rc != 0 ) {
      
      // failed!
      curl_easy_cleanup( curl );
      return -ENOMEM;
   }
   
   ms_client_init_curl_handle( client, curl, url, auth_header );
   
   curl_easy_setopt( curl, CURLOPT_HEADERFUNCTION, ms_client_timing_header_func );
   curl_easy_setopt( curl, CURLOPT_WRITEHEADER, &timing );
   
   // run 
   rc = md_download_run( curl, MS_MAX_MSG_SIZE, buf, buflen );
   
   curl_easy_cleanup( curl );
   SG_safe_free( auth_header );
   
   if( rc != 0 ) {
      
      SG_error("md_download_run('%s') rc = %d\n", url, rc );
      
      if( rc <= -400 && rc >= -499 ) {
         rc = -EPROTO;
      }
      else if( rc <= -500 ) {
         rc = -EREMOTEIO;
      }
   }
   else {
      ms_client_timing_log( &timing );
   }
   
   ms_client_timing_free( &timing );
   return rc;
}


/**
 * @brief Read-lock a client context
 * @return Result from pthread_rwlock_rdlock
 */ 
int ms_client_rlock2( struct ms_client* client, char const* from_str, int lineno ) {
   
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_rlock(%p) from %s:%d\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_rdlock( &client->lock );
}


/**
 * @brief Write-lock a client context
 * @return Result from pthread_rwlock_wrlock
 */
int ms_client_wlock2( struct ms_client* client, char const* from_str, int lineno ) {
   
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_wlock(%p) from %s:%d\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_wrlock( &client->lock );
}


/**
 * @brief Unlock a client context
 * @return Result from pthread_rwlock_unlock
 */
int ms_client_unlock2( struct ms_client* client, char const* from_str, int lineno ) {
   
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_unlock(%p) from %s:%d\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_unlock( &client->lock );
}


/**
 * @brief Read-lock a client context's view
 * @return Result from pthread_rwlock_rdlock
 */
int ms_client_config_rlock2( struct ms_client* client, char const* from_str, int lineno ) {
    
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_config_rlock %p (from %s:%d)\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_rdlock( &client->config_lock );
}


/**
 * @brief Write-lock a client context's view
 * @return Result from pthread_rwlock_wrlock
 */
int ms_client_config_wlock2( struct ms_client* client, char const* from_str, int lineno  ) {
   
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_config_wlock %p (from %s:%d)\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_wrlock( &client->config_lock );
}


/**
 * @brief Unlock a client context's view
 * @return Result from pthread_rwlock_unlock
 */
int ms_client_config_unlock2( struct ms_client* client, char const* from_str, int lineno ) {
   
   if( client->conf->debug_lock ) {
      SG_debug("ms_client_config_unlock %p (from %s:%d)\n", client, from_str, lineno);
   }
   
   return pthread_rwlock_unlock( &client->config_lock );
}


/// Get the current volume config version
uint64_t ms_client_volume_version( struct ms_client* client ) {
   ms_client_config_rlock( client );

   uint64_t ret = client->volume->volume_version;
   ms_client_config_unlock( client );
   return ret;
}


/// Get the current gateway cert bundle version
uint64_t ms_client_cert_version( struct ms_client* client ) {
   ms_client_config_rlock( client );

   uint64_t ret = client->conf->cert_bundle_version;
   ms_client_config_unlock( client );
   return ret;
}


/// Get the Volume ID
uint64_t ms_client_get_volume_id( struct ms_client* client ) {
   ms_client_config_rlock( client );

   uint64_t ret = client->volume->volume_id;

   ms_client_config_unlock( client );
   return ret;
}


/// Get the volume version 
uint64_t ms_client_get_volume_version( struct ms_client* client ) {

   ms_client_config_rlock( client );
   uint64_t ret = client->volume->volume_version;
   ms_client_config_unlock( client );
   return ret;
}


/// Get the volume owner ID 
uint64_t ms_client_get_volume_owner_id( struct ms_client* client ) {
   ms_client_config_rlock( client );

   uint64_t ret = client->volume->volume_owner_id;

   ms_client_config_unlock( client );
   return ret;
}

/// Get the owner ID 
uint64_t ms_client_get_owner_id( struct ms_client* client ) {
   ms_client_config_rlock( client );
   
   uint64_t ret = client->owner_id;
   
   ms_client_config_unlock( client );
   return ret;
}


/**
 * @brief Get the ID of the gateway we're attached to 
 * @return The id on success
 * @retval SG_INVALID_GATEWAY_ID Not attached
 */ 
uint64_t ms_client_get_gateway_id( struct ms_client* client ) {
    
    uint64_t ret = 0;
    
    ms_client_config_rlock( client );
    
    ret = client->gateway_id;
    if( ret == 0 ) {
        ret = SG_INVALID_GATEWAY_ID;
    }
    
    ms_client_config_unlock( client );
    
    return ret;
}

/**
 * @brief Get the Volume name
 * @retval NULL Out of Memory
 */
char* ms_client_get_volume_name( struct ms_client* client ) {
   ms_client_config_rlock( client );

   char* ret = SG_strdup_or_null( client->volume->name );
   
   ms_client_config_unlock( client );
   return ret;
}

/// Get the port num
int ms_client_get_portnum( struct ms_client* client ) {
   ms_client_config_rlock( client );
   
   int ret = client->portnum;
   
   ms_client_config_unlock( client );
   return ret;
}


/**
 * @brief Get the volume block size 
 * @return The volume block size
 */
uint64_t ms_client_get_volume_blocksize( struct ms_client* client ) {
   ms_client_config_rlock( client );

   uint64_t ret = client->volume->blocksize;

   ms_client_config_unlock( client );
   return ret;
}


/**
 * @brief Download the root inode
 * @param[out] *root The root inode
 * @retval 0 Success
 * @retval -ENODATA Couldn't get a root inode.
 * @retval -ENOMEM Out of Memory
 */
int ms_client_get_volume_root( struct ms_client* client, int64_t root_version, int64_t root_nonce, struct md_entry* root ) {

   int rc = 0;
   struct ms_path_ent root_request;
   
   ms_client_config_rlock( client );
   
   rc = ms_client_getattr_request( &root_request, client->volume->volume_id, 0, root_version, root_nonce, NULL );
   if( rc != 0 ) {
      
      ms_client_config_unlock( client );
      return rc;
   }
   
   ms_client_config_unlock( client );
   
   rc = ms_client_getattr( client, &root_request, root );
   
   ms_client_free_path_ent( &root_request, NULL );
   
   if( rc != 0 ) {
      
      SG_error("ms_client_getattr('/') rc = %d\n", rc );
      return rc;
   }
   
   return rc;
}


/**
 * @brief Get a ref to the gateway public key
 * @note The client should be at least read-locked
 */
EVP_PKEY* ms_client_my_pubkey( struct ms_client* client ) {
   return client->gateway_pubkey;
}

/**
 * @brief Get a ref to the gateway private key 
 * @note The client should be at least read-locked
 */
EVP_PKEY* ms_client_my_privkey( struct ms_client* client ) {
   return client->gateway_key;
}

/**
 * @brief Check if an MS operation is an async operation
 * @retval 1 Operation is an UPDATE_ASYNC, CREATE_ASYNC, or DELETE_ASYNC
 * @retval 0 Not an async operation
 */
int ms_client_is_async_operation( int oper ) {
   
   return (oper == ms::ms_request::UPDATE_ASYNC || oper == ms::ms_request::CREATE_ASYNC || oper == ms::ms_request::DELETE_ASYNC );
}

/**
 * @brief Process a gateway message's header
 *
 * In order to detect when we have a stale cert graph.
 * @retval 0 No reload is needed
 * @retval 1 The cert graph must be reloaded 
 * @retval -EINVAL The volumes do not match
 */
int ms_client_need_reload( struct ms_client* client, uint64_t volume_id, uint64_t volume_version, uint64_t cert_bundle_version ) {
   
   int rc = 0;
   
   ms_client_config_rlock( client );
   
   if( client->volume->volume_id != volume_id ) {
      
      ms_client_config_unlock( client );
      return -EINVAL;
   }
   
   // wake up volume reload thread, if there is new cert graph information for us
   if( client->volume->volume_version < volume_version ) {
      rc = 1;
   }
   
   if( client->conf->cert_bundle_version <= 0 || (unsigned)client->conf->cert_bundle_version < cert_bundle_version ) {
      rc = 1;
   }
   
   ms_client_config_unlock( client );
   return rc;
}


/**
 * @brief Get a pointer to a gateway's certificate
 * @note Only call when you're sure that the config can't be reloaded out from under us
 * @return A pointer to the certificate, NULL otherwise
 */
struct ms_gateway_cert* ms_client_get_gateway_cert( struct ms_client* client, uint64_t gateway_id ) {
   
   struct ms_gateway_cert* cert = NULL;
   
   ms_client_config_rlock( client );
  
   ms_cert_bundle::iterator itr = client->certs->find( gateway_id );
   if( itr == client->certs->end() ) {
      
      ms_client_config_unlock( client );
      return NULL;
   }
   else {
      
      cert = itr->second;
   }
   
   ms_client_config_unlock( client );
   
   return cert;
}


/// Get the number of gateway certs
uint64_t ms_client_get_num_gateways( struct ms_client* client ) {

   uint64_t ret = 0;

   ms_client_config_rlock( client );
   ret = client->certs->size();
   ms_client_config_unlock( client );

   return ret;
}


/**
 * @brief Copy in the gateway IDs to the given id_buf
 * @retval -ERANGE  The buf is too small
 * @retval Other The number copied
 */
int ms_client_get_gateway_ids( struct ms_client* client, uint64_t* id_buf, size_t id_buf_len ) {

   int num_copied = 0;

   ms_client_config_rlock( client );

   if( id_buf_len < client->certs->size() ) {
      ms_client_config_unlock( client );
      return -ERANGE;
   }

   for( ms_cert_bundle::iterator itr = client->certs->begin(); itr != client->certs->end(); itr++ ) {

      id_buf[num_copied] = itr->first;
      num_copied++; 
   }

   ms_client_config_unlock( client );
   return num_copied;
}


/**
 * @brief Get a cert's capability bits
 * @return The bitmask on success
 * @retval 0 There is no such gateway (i.e. non-existent gateways have no capabilities)
 */
uint64_t ms_client_get_gateway_caps( struct ms_client* client, uint64_t gateway_id ) {
   
   ms_client_config_rlock( client );
   
   struct ms_gateway_cert* cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {
      
      ms_client_config_unlock( client );
      return 0;
   }
   
   uint64_t bits = cert->caps;
   
   ms_client_config_unlock( client );
   
   return bits;
}


/**
 * @brief Get a gateway's cert version
 * @retval >0 Success, with the version
 * @retval 0 Not found
 */
uint64_t ms_client_get_gateway_cert_version( struct ms_client* client, uint64_t gateway_id ) {

   ms_client_config_rlock( client );

   struct ms_gateway_cert* cert = ms_client_get_gateway_cert( client, gateway_id );
   if( cert == NULL ) {

      ms_client_config_unlock( client );
      return 0;
   }

   uint64_t ver = cert->version;
   ms_client_config_unlock( client );

   return ver;
}


/**
 * @brief Get a list of gateway IDs that have a particular type
 * @param[out] *gateway_ids The gateway IDs
 * @param[out] *num_gateway_ids The number of gateway IDs
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int ms_client_get_gateways_by_type( struct ms_client* client, uint64_t gateway_type, uint64_t** gateway_ids, size_t* num_gateway_ids ) {
   
   size_t count = 0;
   size_t i = 0;
   uint64_t* ret = NULL;
   
   ms_client_config_rlock( client );
   
   // count up 
   for( ms_cert_bundle::iterator itr = client->certs->begin(); itr != client->certs->end(); itr++ ) {
      
      if( itr->second->gateway_type == gateway_type ) {
         
         count++;
         continue;
      }
   }
   
   // allocate and copy in 
   ret = SG_CALLOC( uint64_t, count + 1 );
   if( ret == NULL ) {
      
      ms_client_config_unlock( client );
      return -ENOMEM;
   }
   
   for( ms_cert_bundle::iterator itr = client->certs->begin(); itr != client->certs->end(); itr++ ) {
      
      if( itr->second->gateway_type == gateway_type ) {
         
         ret[i] = itr->second->gateway_id;
         i++;
      }
   }
   
   ms_client_config_unlock( client );
   
   *gateway_ids = ret;
   *num_gateway_ids = count;
   
   return 0;
}

/**
 * @brief Swap the cert bundle
 * @return A pointer to the old cert bundle
 */
ms_cert_bundle* ms_client_swap_gateway_certs( struct ms_client* client, ms_cert_bundle* new_cert_bundle ) {
   
   ms_client_config_wlock( client );
   
   ms_cert_bundle* old_certs = client->certs;
   client->certs = new_cert_bundle;
   
   ms_client_config_unlock( client );
   
   return old_certs;
}


/**
 * @brief Swap the volume cert 
 * @return Pointer to the old volume structure
 * @retval NULL Out of Memory
 */
struct ms_volume* ms_client_swap_volume_cert( struct ms_client* client, ms::ms_volume_metadata* new_volume_cert ) {
   
   struct ms_volume* new_volume = SG_CALLOC( struct ms_volume, 1 );
   if( new_volume == NULL ) {
      return NULL;
   }
   
   int rc = ms_client_volume_init( new_volume, new_volume_cert );
   if( rc != 0 ) {
      SG_safe_free( new_volume );
      return NULL;
   }
   
   ms_client_config_wlock( client );
   
   struct ms_volume* old_vol = client->volume;
   client->volume = new_volume;
   
   ms_client_config_unlock( client );
   
   return old_vol;
}


/**
 * @brief Swap the syndicate public key 
 * @return A pointer to the old syndicate public key
 */
EVP_PKEY* ms_client_swap_syndicate_pubkey( struct ms_client* client, EVP_PKEY* new_syndicate_pubkey ) {
    
    ms_client_config_wlock( client );
    
    EVP_PKEY* old_key = client->syndicate_pubkey;
    client->syndicate_pubkey = new_syndicate_pubkey;
    
    ms_client_config_unlock( client );
    
    return old_key;
}


/**
 * @brief Synchronous method to GET data
 *
 * Expects an ms_reply
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 * @retval -ETIMEDOUT The tranfser could not complete in time 
 * @retval -EAGAIN Signaled to retry the request 
 * @retval -EREMOTEIO The HTTP error is >= 500 
 * @retval -EPROTO The HTTP error was between 400 and 499
 * @retval -EBADMSG The signature didn't match
 * @retval other -errno on socket- and recv-related errors
 * @note Does *NOT* check the error code in reply
 */
int ms_client_read( struct ms_client* client, char const* url, ms::ms_reply* reply ) {
   
   char* buf = NULL;
   off_t buflen = 0;
   int rc = 0;
   
   rc = ms_client_download( client, url, &buf, &buflen );
   
   if( rc != 0 ) {
      SG_error("ms_client_download('%s') rc = %d\n", url, rc );
      return rc;
   }
   
   // parse and verify
   rc = ms_client_parse_reply( client, reply, buf, buflen );
   
   SG_safe_free( buf );
   
   if( rc != 0 ) {
      SG_error("ms_client_parse_reply rc = %d\n", rc );
      
      if( rc == -EINVAL ) {
         rc = -EBADMSG;
      }
   }
   
   return rc;
}
