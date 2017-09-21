/*
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
*/

/**
 * @file storage.cpp
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief Syndicate storage related functionality
 *
 * @see libsyndicate/storage.h
 */

#include "libsyndicate/storage.h"

/**
 * @brief Load a file as a string
 * @return The buffer with the file
 * @retval NULL Error
 */
char* md_load_file_as_string( char const* path, size_t* size ) {
   
   off_t size_or_error = 0;
   char* buf = md_load_file( path, &size_or_error );

   if( buf == NULL ) {
      SG_error("md_load_file('%s') rc = %d\n", path, (int)size_or_error );
      return NULL;
   }

   *size = size_or_error;
   
   char* ret = (char*)realloc( buf, *size + 1 );
   if( ret == NULL ) {
      SG_safe_free( buf );
      return NULL;
   }
   
   ret[ *size ] = 0;

   return ret;
}


/**
 * @brief Safely load secret information as a null-terminated string, ensuring that the memory allocated is mlocked
 * @retval 0 Success
 * @retval <0 errno on stat(2) failure on path
 * @retval -ENODATA if we failed to allocate a buffer of sufficient size for the file referred to by the path 
 * @retval -ENODATA if we failed to open path for reading, or failed to read all of the file
 * @retval -EINVAL if the path does not refer to a regular file (or a symlink to a regular file)
 * @retval -EOVERFLOW if the buf was allocated, but does not contain sufficient space
 */
int md_load_secret_as_string( struct mlock_buf* buf, char const* path ) {
   
   struct stat statbuf;
   int rc = 0;
   
   rc = stat( path, &statbuf );
   if( rc != 0 ) {
      
      rc = -errno;
      SG_error("stat(%s) errno = %d\n", path, rc );
      return rc;
   }
   
   if( !S_ISREG( statbuf.st_mode ) ) {
      
      return -EINVAL;
   }
   
   bool alloced = false;
   
   if( buf->ptr == NULL ) {
      
      rc = mlock_calloc( buf, statbuf.st_size + 1 );
      if( rc != 0 ) {
         
         SG_error("mlock_calloc rc = %d\n", rc );
         return -ENODATA;
      }
      
      alloced = true;
   }
   else if( buf->len <= (size_t)statbuf.st_size ) {
      
      SG_error("insufficient space for %s\n", path );
      return -EOVERFLOW;
   }
   
   FILE* f = fopen( path, "r" );
   if( f == NULL ) {
      rc = -errno;
      
      if( alloced ) {
         mlock_free( buf );
      }
      
      SG_error("fopen(%s) rc = %d\n", path, rc );
      return -ENODATA;
   }
   
   buf->len = fread( buf->ptr, 1, statbuf.st_size, f );
   fclose( f );
   
   if( buf->len != (unsigned)statbuf.st_size ) {
      
      SG_error("Read only %zu of %zu bytes\n", buf->len, statbuf.st_size );
      
      if( alloced ) {
         mlock_free( buf );
      }
      
      return -ENODATA;
   }

   // null-terminate
   char* char_ptr = (char*)buf->ptr;
   char_ptr[ buf->len ] = 0;

   return 0;
}


/**
 * @brief Initialize local storage
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 * @retval <0 Storage-related error (md_mkdirs)
 */
int md_init_local_storage( struct md_syndicate_conf* c ) {
   
   char cwd[PATH_MAX + 1];
   char path[PATH_MAX + 1];
   memset(cwd, 0, PATH_MAX + 1 );
   
   int rc = 0;
   size_t tmp = 0;
   
   char** dirs[] = {
      &c->data_root,
      &c->volumes_path,
      &c->gateways_path,
      &c->users_path,
      &c->drivers_path,
      &c->logs_path,
      &c->syndicate_path,
      &c->certs_root,
      (char**)NULL
   };
   
   // NOTE: matches names of dirs
   char const* dir_names[] = {
      "data",
      "volumes",
      "gateways",
      "users",
      "drivers",
      "logs",
      "syndicate",
      "certs",
      "ipc",
      (char const*)NULL
   };

   // NOTE: must be an absolute path 
   md_dirname( c->config_file_path, cwd );
   if( cwd[0] != '/' ) {
      SG_error("config file path '%s' is not absolute\n", c->config_file_path );
      rc = -EINVAL;
      return rc;
   }

   // expand to full path, and make each directory 
   for( int i = 0; dirs[i] != NULL; i++ ) {
      
      char** dirp = dirs[i];
      
      if( *(dirp) == NULL ) {
         SG_error("Configuration is missing the path to the '%s' directory.  Set it in %s with '%s='\n", dir_names[i], c->config_file_path, dir_names[i]);
         rc = -EINVAL;
         break;
      }
      
      if( **dirp != '/' ) {
         
         // relative path
         md_fullpath( cwd, *dirp, path );
         
         SG_safe_free( *dirp );
         rc = md_expand_path( path, dirp, &tmp );
         
         if( rc != 0 ) {
            break;
         }
      }
      else {
         
         strcpy( path, *dirp );
      }
      
      rc = md_mkdirs( path );
      if( rc != 0 ) {
         SG_error("md_mkdirs('%s') rc = %d\n", path, rc );
         break;
      }
   }
   
   return rc;
}

/**
 * @brief Recursively make a directory.
 * @retval 0 The directory exists at the end of the call.
 * @retval -ENOMEM Out of Memory
 * @retval <0 The directory could not be created.
 */
int md_mkdirs2( char const* dirp, int start, mode_t mode ) {
   
   unsigned int i = start;
   struct stat statbuf;
   int rc = 0;
   char* currdir = SG_CALLOC( char, strlen(dirp) + 1 );
   
   if( currdir == NULL ) {
      return -ENOMEM;
   }
   
   while( i <= strlen(dirp) ) {
      
      if( dirp[i] == '/' || i == strlen(dirp) ) {
         
         strncpy( currdir, dirp, i == 0 ? 1 : i );
         
         rc = stat( currdir, &statbuf );
         if( rc == 0 && !S_ISDIR( statbuf.st_mode ) ) {
            
            SG_safe_free( currdir );
            return -EEXIST;
         }
         if( rc != 0 ) {
            
            rc = mkdir( currdir, mode );
            if( rc != 0 ) {
               
               rc = -errno;
               SG_safe_free(currdir);
               return rc;
            }
         }
      }
      
      i++;
   }
   
   SG_safe_free(currdir);
   return 0;
}

/**
 * @brief Make directories, call md_mkdirs2 with provided mode
 * @return Status of md_mkdirs2
 * @see md_mkdirs2
 */
int md_mkdirs3( char const* dirp, mode_t mode ) {
   return md_mkdirs2( dirp, 0, mode );
}

/**
 * @brief Make directories, call md_mkdirs2 with mode 0755
 * @return Status of md_mkdirs2
 * @see md_mkdirs2
 */
int md_mkdirs( char const* dirp ) {
   return md_mkdirs2( dirp, 0, 0755 );
}

/**
 * @brief Remove a bunch of empty directories
 * @retval 0 Success 
 * @retval -ENOMEM Out of Memory
 * @retval <0 Error from rmdir(2)
 */
int md_rmdirs( char const* dirp ) {
   
   char* dirname = SG_strdup_or_null( dirp );
   if( dirname == NULL ) {
      return -ENOMEM;
   }
   
   char* dirname_buf = SG_CALLOC( char, strlen(dirp) + 1 );
   if( dirname_buf == NULL ) {
      
      SG_safe_free( dirname );
      return -ENOMEM;
   }
   
   int rc = 0;
   
   while( strlen(dirname) > 0 ) {
      
      rc = rmdir( dirname );
      if( rc != 0 ) {
         
         rc = -errno;
         break;
      }
      else {
         
         md_dirname( dirname, dirname_buf );
         strcpy( dirname, dirname_buf );
      }
   }
   
   SG_safe_free( dirname );
   SG_safe_free( dirname_buf );
   return rc;
}

/**
 * @brief Get the path to a cached certificate 
 *
 * @note Path must be long enough--PATH_MAX should be safe--but it will be truncated with '\0'
 */
void md_object_cert_path( char const* cert_path, char const* object_type, char const* object_name, char* path, size_t path_len ) {
   
   snprintf( path, path_len-1, "%s/%s-%s.cert", cert_path, object_type, object_name );
   path[ path_len-1 ] = '\0';
}


/**
 * @brief Load a syndicate public key from disk 
 * @retval 0 Success, and set *key to include the public key 
 * @retval -errno Filesystem-related errors
 */ 
int md_syndicate_pubkey_load( char const* syndicate_dir, char const* syndicate_name, char** syndicate_pubkey_pem, size_t* syndicate_pubkey_pem_len ) {
    
   char path[ PATH_MAX+1 ];
   char* data = NULL;
   off_t data_len = 0;
   
   snprintf( path, PATH_MAX-1, "%s/%s.pub", syndicate_dir, syndicate_name );
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 ) {
       
       SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
       return (int)data_len;
   }
   
   *syndicate_pubkey_pem = data;
   *syndicate_pubkey_pem_len = data_len;
   return 0;
}


/**
 * @brief Load a volume cert from disk
 * @param[out] volume_cert The volume certificate 
 * @retval 0 Success, and populate *volume_cert 
 * @retval -errno Filesystem-related errors
 */
int md_volume_cert_load( char const* cert_path, char const* volume_name, ms::ms_volume_metadata* volume_cert ) {
   
   int rc = 0;
   char path[ PATH_MAX+1 ];
   char* data = NULL;
   off_t data_len = 0;
   
   md_object_cert_path( cert_path, "volume", volume_name, path, PATH_MAX );
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 ) {
      
      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
      return (int)data_len;
   }
   
   rc = md_parse< ms::ms_volume_metadata >( volume_cert, data, data_len );
   SG_safe_free( data );
   
   if( rc != 0 ) {
      
      SG_error("md_parse< ms::ms_volume_metadata >('%s') rc = %d\n", path, rc );
      return rc;
   }
   
   return rc;
}


/**
 * @brief Get a cached gateway certificate 
 * @retval 0 Success, and populate *cert on success 
 * @retval -ENOMEM Out of Memory
 * @retval -ENOENT Not found
 * @retval Other -errno related to filesystem errors
 */
int md_gateway_cert_load( char const* cert_path, char const* gateway_name, ms::ms_gateway_cert* cert ) {
   
   int rc = 0;
   char path[ PATH_MAX+1 ];
   char* data = NULL;
   off_t data_len = 0;
   
   md_object_cert_path( cert_path, "gateway", gateway_name, path, PATH_MAX );
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 ) {
      
      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
      return (int)data_len;
   }
   
   rc = md_parse< ms::ms_gateway_cert >( cert, data, data_len );
   SG_safe_free( data );
   
   if( rc != 0 ) {
      
      SG_error("md_parse< ms::ms_gateway_cert >('%s') rc = %d\n", path, rc );
      return rc;
   }
   
   return 0;
}


/**
 * @brief Get a gateway's private key from disk
 * @param[out] private_key The private key
 * @retval 0 Success, and populate *private_key 
 * @retval -ENOMEM Out of Memory 
 * @retval other -errno Related to filesystem errors
 */
int md_gateway_private_key_load( char const* gateways_root, char const* gateway_name, struct mlock_buf* private_key ) {
   
   int rc = 0;
   char path[ PATH_MAX+1 ];
   
   memset( path, 0, PATH_MAX+1 );
   snprintf( path, PATH_MAX-1, "%s/%s.pkey", gateways_root, gateway_name );
   
   rc = md_load_secret_as_string( private_key, path );
   if( rc != 0 ) {
      
      SG_error("md_load_secret_as_string('%s') rc = %d\n", path, rc );
      return rc;
   }
   
   return rc;
}


/**
 * @brief Load a cached user cert from disk 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -errno Filesystem-related errors
 */
int md_user_cert_load( char const* certs_path, char const* username, ms::ms_user_cert* user_cert ) {
   
   int rc = 0;
   char* data = NULL;
   long data_len = 0;
   char path[ PATH_MAX+1 ];
   
   md_object_cert_path( certs_path, "user", username, path, PATH_MAX );
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 || data == NULL ) {
      
      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
      return (int)data_len;
   }
   
   rc = md_parse< ms::ms_user_cert >( user_cert, data, data_len );
   SG_safe_free( data );
   
   if( rc != 0 ) {
      SG_error("Failed to load user cert '%s'\n", path );
      return rc;
   }
   
   return 0;
}


/**
 * @brief Load a cached cert bundle from disk 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -errno On filesystem-related errors
 */
int md_cert_bundle_load( char const* certs_path, char const* volume_name, SG_messages::Manifest* cert_bundle ) {
   
   int rc = 0;
   char* data = NULL;
   long data_len = 0;
   char path[ PATH_MAX+1 ];
   
   snprintf( path, PATH_MAX-1, "%s/%s.bundle", certs_path, volume_name );
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 || data == NULL ) {
      
      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
      return (int)data_len;
   }
   
   rc = md_parse< SG_messages::Manifest >( cert_bundle, data, data_len );
   SG_safe_free( data );
   
   if( rc != 0 ) {
      SG_error("Failed to load user cert '%s'\n", path );
      return rc;
   }
   
   return 0;
}


/**
 * @brief Load a cached driver from disk
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -errno Filesystem-related errors
 */
int md_driver_load( char const* certs_path, char const* hash, char** driver_text, size_t* driver_text_len ) {

   char* data = NULL;
   long data_len = 0;
   char path[ PATH_MAX+1 ];

   snprintf( path, PATH_MAX-1, "%s/driver-%s", certs_path, hash );

   data = md_load_file( path, &data_len );
   if( data_len < 0 || data == NULL ) {

      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len );
      return (int)data_len;
   }

   *driver_text = data;
   *driver_text_len = data_len;
   return 0;
}



/**
 * @brief Load the cached cert bundle version 
 * @retval 0 Success 
 * @retval -EPERM Failure
 * @retval -ENOMEM Out of Memory 
 * @retval -errno Filesystem-related error
 */
int md_cert_bundle_version_load( char const* certs_path, char const* volume_name, uint64_t* cert_bundle_version ) {
   
   char path[ PATH_MAX+1 ];
   char* data = NULL;
   long data_len = 0;
   uint64_t ret = 0;
   char* tmp = NULL;
   
   snprintf( path, PATH_MAX-1, "%s/bundle.version", certs_path );
   path[ PATH_MAX ] = '\0';
   
   data = md_load_file( path, &data_len );
   if( data_len < 0 ) {
      
      SG_error("md_load_file('%s') rc = %d\n", path, (int)data_len);
      return (int)data_len;
   }
   
   ret = (uint64_t)strtoull( data, &tmp, 10 );
   if( ret == 0 && (*tmp != '\0' && *tmp != '\n') ) {
      SG_error("Invalid cert bundle version in '%s'\n", path );
      return -EPERM;
   }
   
   *cert_bundle_version = ret;
   return 0;
}


