/*
   Copyright 2015 The Trustees of Princeton University

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

#include "libsyndicate/libsyndicate.h"
#include "libsyndicate/driver.h"
#include "libsyndicate/crypt.h"
#include "libsyndicate/gateway.h"

struct SG_driver {
  
   struct SG_chunk driver_conf;     // serialized driver config
   struct SG_chunk driver_secrets;  // serialized driver secrets
   struct SG_chunk driver_text;        // driver code
   
   void* cls;           // supplied by the driver on initialization
   int running;         // set to non-zero of this driver is initialized
   
   pthread_rwlock_t reload_lock;                // if write-locked, no method can be called here (i.e. the driver is reloading)

   // driver processes: map role to group of processes that implement it 
   SG_driver_proc_group_t* groups;

   // driver info
   char* exec_str;
   char** roles;
   size_t num_roles;
   int num_instances;   // number of instances of each role 

   // pointer to global conf 
   struct md_syndicate_conf* conf;
};


// alloc a driver 
struct SG_driver* SG_driver_alloc(void) {
   return SG_CALLOC( struct SG_driver, 1 );
}

// convert a reqdat to a fully-qualified chunk path, to be fed into the driver worker.
// the string will be terminated with a newline, and a null.
// return the null-terminated string on success
// return NULL on OOM or invalid request
char* SG_driver_reqdat_to_path( struct SG_request_data* reqdat ) {
   
   char* ret = NULL;
   size_t len = 0;
   
   if( reqdat->user_id == SG_INVALID_USER_ID ) {
      return NULL;
   }
   
   if( SG_request_is_block( reqdat ) ) {
      
      // include owner, volume, file, version, block, block version
      len = 51 + 51 + 51 + 51 + 51 + 51 + 11;
      
      ret = SG_CALLOC( char, len + 1 );
      if( ret == NULL ) {
         
         return NULL;
      }
      
      snprintf( ret, len, "%" PRIu64 ":/%" PRIu64 "/%" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "]",
                           reqdat->user_id, reqdat->volume_id, reqdat->file_id, reqdat->file_version, reqdat->block_id, reqdat->block_version );
      
      return ret;
   }
   else if( SG_request_is_manifest( reqdat ) ) {
      
      // include owner, volume, file, version, manifest timestamp
      len = 51 + 51 + 51 + 51 + 51 + 51 + 11;
      
      ret = SG_CALLOC( char, len + 1 );
      if( ret == NULL ) {
         
         return NULL;
      }
      
      snprintf( ret, len, "%" PRIu64 ":/%" PRIu64 "/%" PRIX64 ".%" PRId64 "/manifest.%ld.%ld",
                          reqdat->user_id, reqdat->volume_id, reqdat->file_id, reqdat->file_version, reqdat->manifest_timestamp.tv_sec, reqdat->manifest_timestamp.tv_nsec );
      
      return ret;
   }
   else {
      
      return NULL;
   }
}


// load a string as a JSON object 
// return 0 on success, and fill in *jobj_ret 
// return -ENOMEM on OOM
// return -EINVAL if we failed to parses
static int SG_parse_json_object( struct json_object** jobj_ret, char const* obj_json, size_t obj_json_len ) {
   
   char* tmp = SG_CALLOC( char, obj_json_len + 1 );
   if( tmp == NULL ) {
      return -ENOMEM;
   }
   
   memcpy( tmp, obj_json, obj_json_len );
   
   // obj_json should be a valid json string that contains a single dictionary.
   struct json_tokener* tok = json_tokener_new();
   if( tok == NULL ) {
      
      SG_safe_free( tmp );
      return -ENOMEM;
   }
   
   struct json_object* jobj = json_tokener_parse_ex( tok, tmp, obj_json_len );
   
   json_tokener_free( tok );
   
   if( jobj == NULL ) {
      
      SG_error("Failed to parse JSON object %p '%s'\n", obj_json, tmp );
      
      SG_safe_free( tmp );
      
      return -EINVAL;
   }
   
   SG_safe_free( tmp );
   
   // should be an object
   enum json_type jtype = json_object_get_type( jobj );
   if( jtype != json_type_object ) {
      
      SG_error("%s", "JSON config is not a JSON object\n");
      
      json_object_put( jobj );
      return -EINVAL;
   }
   
   *jobj_ret = jobj;
   return 0;
}


// decode and decrypt secrets and put the plaintext into an mlock'ed buffer 
// return 0 on success
// return -ENOMEM on OOM 
// return -EINVAL on failure to parse
int SG_driver_decrypt_secrets( EVP_PKEY* gateway_pubkey, EVP_PKEY* gateway_pkey, char** ret_buf, size_t* ret_buflen, char const* driver_secrets_b64, size_t driver_secrets_b64_len ) {
   
   // deserialize...
   char* obj_ctext = NULL;
   size_t obj_ctext_len = 0;
   
   int rc = 0;
   
   rc = md_base64_decode( driver_secrets_b64, driver_secrets_b64_len, &obj_ctext, &obj_ctext_len );
   if( rc != 0 ) {
      
      SG_error("md_base64_decode rc = %d\n", rc );
      return -EINVAL;
   }
   
   // decrypt...
   char* obj_buf = NULL;
   size_t obj_buflen = 0;
   
   rc = md_decrypt( gateway_pubkey, gateway_pkey, obj_ctext, obj_ctext_len, &obj_buf, &obj_buflen );
   
   SG_safe_free( obj_ctext );
   
   if( rc != 0 ) {
      
      SG_error("md_decrypt rc = %d\n", rc );
      return -EINVAL;
   }
   
   *ret_buf = obj_buf;
   *ret_buflen = obj_buflen;
   
   return rc;
}


// parse the config
// return 0 on success
// return -ENOMEM on OOM 
// return -EINVAL on failure to parse
static int SG_parse_driver_config( struct SG_chunk* config, char const* driver_config_b64, size_t driver_config_b64_len ) {
   
   char* obj_buf = NULL;
   size_t obj_buflen = 0;
   int rc = 0;
  
   // deserialize 
   rc = md_base64_decode( driver_config_b64, driver_config_b64_len, &obj_buf, &obj_buflen );
   if( rc != 0 ) {
      
      SG_error("md_base64_decode rc = %d\n", rc );
      return rc; 
   }

   SG_chunk_init( config, obj_buf, obj_buflen );
   return 0;
}


// parse the secrets 
// return 0 on success
// return -ENOMEM on OOM 
// return -EINVAL on failure to parse
static int SG_parse_driver_secrets( EVP_PKEY* gateway_pubkey, EVP_PKEY* gateway_pkey, struct SG_chunk* secrets, char const* driver_secrets_b64, size_t driver_secrets_b64_len ) {
   
   char* obj_buf = NULL;
   size_t obj_buflen = 0;
   int rc = 0;
   
   // decrypt json
   rc = SG_driver_decrypt_secrets( gateway_pubkey, gateway_pkey, &obj_buf, &obj_buflen, driver_secrets_b64, driver_secrets_b64_len );
   if( rc != 0 ) {
      
      SG_error("Failed to decrypt, rc = %d\n", rc );
      return rc;
   }

   SG_chunk_init( secrets, obj_buf, obj_buflen );
   return 0;
}


// load a string by key 
// returns a reference to the value in the json object on success (do NOT free or modify it)
// return NULL if not found, or if OOM
static char const* SG_load_json_string_by_key( struct json_object* obj, char const* key, size_t* _val_len ) {
   
   // look up the keyed value
   struct json_object* key_obj = NULL;
   
   json_object_object_get_ex( obj, key, &key_obj );
   if( key_obj == NULL ) {
      
      SG_error("No such key '%s'\n", key );
      return NULL;
   }
   
   // verify it's a string 
   enum json_type jtype = json_object_get_type( key_obj );
   if( jtype != json_type_string ) {
      
      SG_error("'%s' is not a string\n", key );
      return NULL;
   }
   
   char const* val = json_object_get_string( key_obj );
   if( val == NULL ) {
      
      // OOM
      return NULL;
   }
   
   *_val_len = strlen(val);  // json_object_get_string_len( val );
   return val;
}


// load a chunk of data by key directly 
// return 0 on success, and set *val and *val_len to the value
// return -ENOENT if there is no such key 
// return -EINVAL on parse error 
// return -ENOMEM if OOM
static int SG_parse_json_b64_string( struct json_object* toplevel_obj, char const* key, char** val, size_t* val_len ) {
   int rc = 0;
   
   // look up the keyed value
   size_t b64_len = 0;
   char const* b64 = SG_load_json_string_by_key( toplevel_obj, key, &b64_len );
   
   if( b64 == NULL || b64_len == 0 ) {
      
      SG_error("No value for '%s'\n", key);
      rc = -ENOENT;
   }
   else {
      
      char* tmp = NULL;
      size_t tmp_len = 0;
      
      // load it directly...
      rc = md_base64_decode( b64, b64_len, &tmp, &tmp_len );
      if( rc != 0 ) {
         
         SG_error("md_base64_decode('%s') rc = %d\n", key, rc );
      }
      else {
         
         *val = tmp;
         *val_len = tmp_len;
      }
   }
   
   return rc;
}


// parse a serialized driver, encoded as a JSON object
// A driver is a JSON object that can have a "config", "secrets", and/or "driver" fields.
// A "config" field is JSON object that maps string keys to string values--it gets loaded as an SG_driver_conf_t.
// A "secrets" field is an base64-encoded *encrypted* string that decrypts to a JSON object that maps string keys to string values.
//    The ciphertext gets verified with the given public key, and decrypted with the given private key.  It gets parsed to an SG_driver_secrets_t.
// A "driver" field is a base64-encoded binary string that encodes some gateway-specific functionality.
// return 0 on success, and populate *driver
// return -ENOMEM on OOM
static int SG_parse_driver( struct SG_driver* driver, char const* driver_full, size_t driver_full_len, EVP_PKEY* pubkey, EVP_PKEY* privkey ) {
      
   // driver_text should be a JSON object...
   struct json_object* toplevel_obj = NULL;
   struct SG_chunk driver_conf;
   struct SG_chunk driver_secrets;

   memset( &driver_conf, 0, sizeof(struct SG_chunk) );
   memset( &driver_secrets, 0, sizeof(struct SG_chunk) );

   char* driver_text = NULL;
   size_t driver_text_len = 0;
   int rc = 0;

   const char* config_b64 = NULL;
   size_t config_b64_len = 0;
   
   const char* secrets_b64 = NULL;
   size_t secrets_b64_len = 0;

   rc = SG_parse_json_object( &toplevel_obj, driver_full, driver_full_len );
   if( rc != 0 ) {
      
      SG_error("SG_parse_json_object rc = %d\n", rc );
      return -EINVAL;
   }
   
   // get the driver conf JSON 
   config_b64 = SG_load_json_string_by_key( toplevel_obj, "config", &config_b64_len );
   if( config_b64 != NULL && config_b64_len != 0 ) {
      
      // load it
      rc = SG_parse_driver_config( &driver_conf, config_b64, config_b64_len );
      if( rc != 0 ) {
         
         SG_error("SG_parse_driver_config rc = %d\n", rc );
         json_object_put( toplevel_obj );
         return rc;
      }
   }
   
   // get the driver secrets JSON 
   secrets_b64 = SG_load_json_string_by_key( toplevel_obj, "secrets", &secrets_b64_len );
   if( secrets_b64 != NULL || secrets_b64_len != 0 ) {
      
      // load it 
      rc = SG_parse_driver_secrets( pubkey, privkey, &driver_secrets, secrets_b64, secrets_b64_len );
      if( rc != 0 ) {
         SG_error("SG_parse_driver_secrets rc = %d\n", rc );
         SG_chunk_free( &driver_conf );
         json_object_put( toplevel_obj );
         return rc;
      }
   }
   
   // requested driver?
   rc = SG_parse_json_b64_string( toplevel_obj, "driver", &driver_text, &driver_text_len );
   
   // not an error if not present...
   if( rc == -ENOENT ) {
      rc = 0;
   }
   else if( rc != 0 ) {
      SG_error("SG_parse_json_b64_string('driver') rc = %d\n", rc );
      SG_chunk_free( &driver_conf );
      SG_chunk_free( &driver_secrets );
      json_object_put( toplevel_obj );
      return rc;
   }
   
   // instantiate driver
   SG_chunk_free( &driver->driver_conf );
   driver->driver_conf = driver_conf;

   SG_chunk_free( &driver->driver_secrets );
   driver->driver_secrets = driver_secrets;

   SG_chunk_free( &driver->driver_text );
   SG_chunk_init( &driver->driver_text, driver_text, driver_text_len );
   
   // free memory
   json_object_put( toplevel_obj );
   return rc;
}


// read-lock a driver
int SG_driver_rlock( struct SG_driver* driver ) {
   return pthread_rwlock_rdlock( &driver->reload_lock );
}


// write-lock a driver
int SG_driver_wlock( struct SG_driver* driver ) {
   return pthread_rwlock_wrlock( &driver->reload_lock );
}

// unlock a driver
int SG_driver_unlock( struct SG_driver* driver ) {
   return pthread_rwlock_unlock( &driver->reload_lock );
}


// initialize a driver's worker processes
// gift it a set of initialized process groups
// return 0 on success
// return -ENOMEM on OOM
static int SG_driver_init_procs( struct SG_driver* driver, char** const roles, struct SG_proc_group** groups, size_t num_groups ) {

    driver->groups = SG_safe_new( SG_driver_proc_group_t() );
    if( driver->groups == NULL ) {
       return -ENOMEM;
    }

    for( size_t i = 0; i < num_groups; i++ ) {
       try {
          (*driver->groups)[ string(roles[i]) ] = groups[i];
       }
       catch( bad_alloc& ba ) {

          SG_safe_delete( driver->groups );
          memset( driver, 0, sizeof(struct SG_driver) );
          return -ENOMEM;
       }
    }

    return 0;
}


// initialize a driver from a JSON object representation
// validate it using the given public key.
// decrypt the driver secrets using the private key.
// return 0 on success, and populate *driver 
// return -ENOMEM on OOM
int SG_driver_init( struct SG_driver* driver, struct md_syndicate_conf* conf,
                    EVP_PKEY* pubkey, EVP_PKEY* privkey,
                    char const* exec_str, char** const roles, size_t num_roles, int num_instances,
                    char const* driver_text, size_t driver_text_len ) {
  
   SG_debug("Initialize driver sandbox '%s'\n", exec_str);

   memset( driver, 0, sizeof(struct SG_driver) );
   
   char* exec_str_dup = SG_strdup_or_null( exec_str );
   char** roles_dup = SG_CALLOC( char*, num_roles );

   if( roles_dup != NULL ) {

       for( size_t i = 0; i < num_roles; i++ ) {
          roles_dup[i] = SG_strdup_or_null( roles[i] );
          if( roles_dup[i] == NULL ) {

             SG_FREE_LISTV( roles_dup, num_roles, free );
             break;
          }
       }
   }
   
   if( exec_str_dup == NULL || roles_dup == NULL ) {
      
      SG_safe_delete( exec_str_dup );
      SG_safe_free( roles_dup );
      return -ENOMEM;
   }
   
   // load up the config, secrets, and driver
   int rc = SG_parse_driver( driver, driver_text, driver_text_len, pubkey, privkey );
   if( rc != 0 ) {
      
      SG_error("SG_parse_driver rc = %d\n", rc );
      
      return rc;
   }
   
   // intialize the driver 
   rc = pthread_rwlock_init( &driver->reload_lock, NULL );
   if( rc != 0 ) {
      
      return rc;
   }
  
   // load the information into the driver 
   driver->exec_str = exec_str_dup;
   driver->roles = roles_dup;
   driver->num_roles = num_roles;
   driver->num_instances = num_instances;
   driver->conf = conf;
    
   return rc;
}


// spawn a driver's process groups
// return 0 on success
// return -ENOMEM on OOM
// NOT THREAD SAFE: the driver must be under mutual exclusion 
int SG_driver_procs_start( struct SG_driver* driver ) {
   
   int rc = 0;
   struct SG_proc_group** groups = NULL;
   struct SG_proc** initial_procs = NULL;
   int wait_rc = 0;

   // do we even have a driver?
   if( driver->driver_text.data == NULL ) {
      driver->groups = NULL;
      return 0;
   }

   groups = SG_CALLOC( struct SG_proc_group*, driver->num_roles );
   if( groups == NULL ) {
      return -ENOMEM;
   }

   initial_procs = SG_CALLOC( struct SG_proc*, driver->num_roles * driver->num_instances );
   if( initial_procs == NULL ) {
      SG_safe_free( groups );
      return -ENOMEM;
   }

   for( size_t i = 0; i < driver->num_roles; i++ ) {
      
      // each role gets its own group
      groups[i] = SG_proc_group_alloc( 1 );
      if( groups[i] == NULL ) {

         // OOM
         rc = -ENOMEM;
         goto SG_driver_procs_start_finish;
      }
         
      // set it up
      rc = SG_proc_group_init( groups[i] );
      if( rc != 0 ) {

         goto SG_driver_procs_start_finish;
      }

      // create all instances of this role
      for( int j = 0; j < driver->num_instances; j++ ) {

         int proc_idx = i * driver->num_instances + j;

         // create all instances of this process
         initial_procs[proc_idx] = SG_proc_alloc( 1 );
         if( initial_procs[proc_idx] == NULL ) {

            rc = -ENOMEM;
            goto SG_driver_procs_start_finish;
         }
      }
   }
   
   for( size_t i = 0; i < driver->num_roles; i++ ) {
     
      for( int j = 0; j < driver->num_instances; j++ ) {

          int proc_idx = i * driver->num_instances + j;

          SG_debug("Start: %s %s (instance %d)\n", driver->exec_str, driver->roles[i], j );

          // start this process 
          rc = SG_proc_start( initial_procs[proc_idx], driver->exec_str, driver->roles[i], driver->conf->helper_env, &driver->driver_conf, &driver->driver_secrets, &driver->driver_text );
          if( rc != 0 ) {

             SG_debug("Wait for instance '%s' (%d) to die\n", driver->roles[i], SG_proc_pid( initial_procs[proc_idx] ) );
             wait_rc = SG_proc_stop( initial_procs[proc_idx], 0 );
             if( wait_rc != 0 ) {
                SG_error("SG_proc_wait('%s' %d) rc = %d\n", driver->roles[i], SG_proc_pid( initial_procs[proc_idx] ), wait_rc );
             }
            
             SG_proc_free( initial_procs[proc_idx] );
             initial_procs[proc_idx] = NULL;

             if( rc == -ENOSYS ) {
                SG_warn("Driver does not implement '%s'\n", driver->roles[i] );
                rc = 0;
                continue;
             }
        
             else { 
                 SG_error("SG_proc_start('%s %s') rc = %d\n", driver->exec_str, driver->roles[i], rc );
                 goto SG_driver_procs_start_finish;
             }
          }
          else { 
              rc = SG_proc_group_add( groups[i], initial_procs[proc_idx] );
              if( rc != 0 ) {
         
                 SG_error("SG_proc_group_insert(%zu, %d) rc = %d\n", i, SG_proc_pid( initial_procs[proc_idx] ), rc );
                 goto SG_driver_procs_start_finish;
              }
          }
      }
   }
   
SG_driver_procs_start_finish:

   if( rc != 0 ) {
      
      // failed to start helpers 
      // shut them all down
      for( size_t i = 0; i < driver->num_roles; i++ ) {

         if( groups[i] == NULL ) {
            continue;
         }

         if( SG_proc_group_size( groups[i] ) > 0 ) {
            
            SG_proc_group_stop( groups[i], 1 );
         }

         else {
           
            for( int j = 0; j < driver->num_instances; j++ ) { 

                int proc_idx = i * driver->num_instances + j;

                if( initial_procs[proc_idx] != NULL ) {
                    SG_proc_stop( initial_procs[proc_idx], 1 );
                    SG_proc_free( initial_procs[proc_idx] );
                }
            }
         }
         
         SG_proc_group_free( groups[i] );
         SG_safe_free( groups[i] );
         groups[i] = NULL;
      }

      SG_safe_free( groups );
   }
   else {

      // install to driver
      SG_driver_init_procs( driver, driver->roles, groups, driver->num_roles );
      SG_safe_free( groups );
   }
   
   // free memory 
   SG_safe_free( initial_procs );
   return rc;
}


// stop a driver's running processes 
// return 0 on success
// NOT THREAD SAFE--caller must lock the driver
int SG_driver_procs_stop( struct SG_driver* driver ) {

   struct SG_proc_group* group = NULL;
   int rc = 0;

   // if there are no processes, then do nothing 
   if( driver->groups == NULL ) {
      return 0;
   }

   // ask the workers to stop
   for( size_t i = 0; i < driver->num_roles; i++ ) {
      
      SG_debug("Stop process group (role '%s')\n", driver->roles[i]); 

      try {
         group = (*driver->groups)[ string(driver->roles[i]) ];
      }
      catch( bad_alloc& ba ) {
         return -ENOMEM;
      }
      
      SG_proc_group_kill( group, SIGINT );
   }
   
   // wait for children to get the signal...
   sleep(1);
   
   for( size_t i = 0; i < driver->num_roles; i++ ) {
     
      try {
         string role(driver->roles[i]);
         group = (*driver->groups)[ role ];
         driver->groups->erase( role );
      }
      catch( bad_alloc& ba ) {
         return -ENOMEM;
      }
       
      rc = SG_proc_group_tryjoin( group );
      if( rc > 0 ) {
         
         // kill the stragglers 
         SG_debug("Killing process group (role '%s')\n", driver->roles[i]);
         SG_proc_group_kill( group, SIGKILL );

         SG_proc_group_tryjoin( group );
      }
      
      // clean up 
      SG_proc_group_free( group );
      SG_safe_free( group );
   }

   SG_safe_delete( driver->groups );
   driver->groups = NULL;
   
   return 0;
}


// reload the driver from a JSON object representation.
// return 0 on success 
// return -ENOMEM on OOM 
// return -EINVAL on failure to parse, or if driver_text is NULL
// return -EPERM if we were unable to start the driver processes
int SG_driver_reload( struct SG_driver* driver, EVP_PKEY* pubkey, EVP_PKEY* privkey, char const* driver_text, size_t driver_text_len ) {
   
   if( driver_text == NULL ) {
      SG_error("%s", "BUG: no driver text given\n");
      exit(1);
      return -EINVAL;
   }

   SG_driver_wlock( driver );
   
   int reload_rc = 0;
   int rc = 0;
  
   rc = SG_parse_driver( driver, driver_text, driver_text_len, pubkey, privkey );
   if( rc != 0 ) {
      
      SG_error("SG_parse_driver rc = %d\n", rc );
      
      SG_driver_unlock( driver );
      return -EPERM;
   }

   // restart the workers, if they're running
   if( driver->groups != NULL ) {
    
      for( SG_driver_proc_group_t::iterator itr = driver->groups->begin(); itr != driver->groups->end(); itr++ ) {
         
         struct SG_proc_group* group = itr->second;
         
         SG_debug("Reload process group %p (%s)\n", group, itr->first.c_str() ); 
      
         // do not allow any subsequent requests for this group
         SG_proc_group_wlock( group );
         rc = SG_proc_group_reload( group, driver->exec_str, &driver->driver_conf, &driver->driver_secrets, &driver->driver_text );
         SG_proc_group_unlock( group );
         
         if( rc != 0 ) {

            SG_error("SG_proc_group_reload('%s', '%s') rc = %d\n", driver->exec_str, itr->first.c_str(), rc );
            reload_rc = -EPERM;
            break;
         }
      }
   }

   if( rc == 0 ) {
      rc = reload_rc;
   }
   
   SG_driver_unlock( driver );
   return rc;
}


// shut down the driver 
// stop any running processes
// alwyas succeeds
int SG_driver_shutdown( struct SG_driver* driver ) {
   
   // call the driver shutdown...
   int rc = 0;
   
   SG_driver_wlock( driver );
   SG_chunk_free( &driver->driver_conf );
   SG_chunk_free( &driver->driver_secrets );

   if( driver->groups != NULL ) {

      // running!
      SG_driver_procs_stop( driver );
   }

   SG_FREE_LISTV( driver->roles, driver->num_roles, free );
   SG_safe_free( driver->exec_str );

   SG_chunk_free( &driver->driver_text );

   SG_driver_unlock( driver );
   pthread_rwlock_destroy( &driver->reload_lock );
   
   memset( driver, 0, sizeof(struct SG_driver) );
   return rc;
}


// get the value of a driver parameter (e.g. 'config', 'secrets', etc).  It will not be decoded in any way (i.e. it might be b64-encoded)
// return 0 on success, and set *value and *value_len accordingly 
// return -ENOMEM on OOM 
// return -ENOENT if the key is not specified
// return -EINVAL if driver_text isn't parseable json 
int SG_driver_get_string( char const* driver_text, size_t driver_text_len, char const* key, char** value, size_t* value_len ) {
   
   int rc = 0;
   
   // driver_text should be a JSON object...
   struct json_object* toplevel_obj = NULL;
   
   rc = SG_parse_json_object( &toplevel_obj, driver_text, driver_text_len );
   if( rc != 0 ) {
      
      SG_error("SG_parse_json_object rc = %d\n", rc );
      return -EINVAL;
   }
   
   // get the driver conf JSON 
   size_t json_len = 0;
   char const* json_text = SG_load_json_string_by_key( toplevel_obj, key, &json_len );
   
   if( json_text == NULL ) {
      
      // not found
      json_object_put( toplevel_obj );
      return -ENOENT;
   }
   
   char* ret = SG_CALLOC( char, json_len + 1 );
   if( ret == NULL ) {
      
      // OOM 
      json_object_put( toplevel_obj );
      return -ENOMEM;
   }
   
   memcpy( ret, json_text, json_len );
   *value = ret;
   *value_len = json_len;
   
   json_object_put( toplevel_obj );
   return rc;
}


// get the value of a driver parameter as an SG_chunk.
// base64-decode it, and put the decoded data into the *chunk
// return 0 on success, and populate *chunk
// return -ENOMEM on OOM 
// return -EINVAL if the field is not base64-encoded
int SG_driver_get_chunk( char const* driver_text, size_t driver_text_len, char const* key, struct SG_chunk* chunk ) {

   int rc = 0;
   char* ret_data = NULL;
   size_t ret_data_len = 0;
   char* chunk_data = NULL;
   size_t chunk_len = 0;
   
   // look up the value 
   rc = SG_driver_get_string( driver_text, driver_text_len, key, &ret_data, &ret_data_len );
   if( rc != 0 ) {
      return rc;
   }

   // decode it
   rc = md_base64_decode( ret_data, ret_data_len, &chunk_data, &chunk_len );
   SG_safe_free( ret_data );
  
   if( rc != 0 ) {
      return rc;
   }

   chunk->data = chunk_data;
   chunk->len = chunk_len;
   return rc;
}


// get a pointer to a proc group
// NOTE: the driver can get reloaded intermittently, and the processes in the group can die unexpectedly.
// However, the group will not be freed by the driver, or altered over the course of the gateway's lifetime.
// The caller should lock the group to prevent the driver from adding/removing processes in it, though.
struct SG_proc_group* SG_driver_get_proc_group( struct SG_driver* driver, char const* proc_group_name ) {

   if( driver->groups == NULL ) {
      return NULL;
   }

   struct SG_proc_group* ret = NULL;

   SG_driver_rlock( driver );
   try {
       SG_driver_proc_group_t::iterator itr = driver->groups->find( string(proc_group_name) );
       if( itr != driver->groups->end() ) {
          ret = itr->second;
       }
   }
   catch( bad_alloc& ba ) {
       SG_driver_unlock( driver );
       return NULL;
   }

   SG_driver_unlock( driver );
   return ret;
}


