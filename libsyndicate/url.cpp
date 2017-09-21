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
 * @file libsyndicate/url.cpp
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief Support URL functionality
 *
 * @see libsyndicate/url.h
 */

#include "libsyndicate/url.h"
#include "libsyndicate/ms/ms-client.h"

/**
 * @brief Split a uint64 into four uint16s
 *
 * @note Assume i is litte-endian; otherwise convert it
 */
static void md_url_split_uint64( uint64_t i, uint16_t* o ) {
   if( htonl( 1234 ) == 1234 ) {
      // i is big endian...
      i = htole64( i );
   }
   o[0] = (i & (uint64_t)0xFFFF000000000000LL) >> 48;
   o[1] = (i & (uint64_t)0x0000FFFF00000000LL) >> 32;
   o[2] = (i & (uint64_t)0x00000000FFFF0000LL) >> 16;
   o[3] = (i & (uint64_t)0x000000000000FFFFLL);
}

/**
 * @brief Convert a file ID to a file path, using each byte as a directory name.
 * @retval NULL Out of Memory
 */
static char* md_url_path_from_file_id( uint64_t file_id ) {
   uint16_t file_id_parts[4];
   md_url_split_uint64( file_id, file_id_parts );

   char* ret = SG_CALLOC( char, 21 );
   if( ret == NULL ) {
      return NULL;
   }
   
   sprintf(ret, "/%04X/%04X/%04X/%04X", file_id_parts[0], file_id_parts[1], file_id_parts[2], file_id_parts[3] );
   return ret;
}

/**
 * @brief Generate a block url, based on whether or not it is locally coordinated
 *
 * If local is true, then prefix should be the path on disk
 * If local is false, then prefix should be the content url
 * @retval URL Success
 * @retval NULL Out of Memory
 */
static char* md_url_block_url( char const* prefix, uint64_t volume_id, uint64_t gateway_id, char const* fs_path, uint64_t file_id, int64_t file_version, uint64_t block_id, int64_t block_version, bool local, bool staging ) {

   int base_len = 25 + 1 + 25 + 1 + strlen(fs_path) + 1 + 25 + 1 + 25 + 1 + 25 + 1 + 25 + 1 + 25 + 1;
   char* ret = NULL;

   if( local ) {
      // local
      if( staging ) {
         // extra "/staging/"
         base_len += 10;
      }

      ret = SG_CALLOC( char, strlen(SG_LOCAL_PROTO) + 1 + strlen(prefix) + 1 + base_len );
      if( ret == NULL ) {
         return NULL;
      }
      
      if( staging ) {
         sprintf(ret, "%s%s%" PRIu64 "/staging/%" PRIu64 "/%s.%" PRIX64 ".%" PRId64 "/%" PRIu64 ".%" PRId64,
                SG_LOCAL_PROTO, prefix, volume_id, gateway_id, fs_path, file_id, file_version, block_id, block_version );
      }
      else {
         sprintf(ret, "%s%s%" PRIu64 "/%" PRIu64 "%s.%" PRIX64 ".%" PRId64 "/%" PRIu64 ".%" PRId64,
                SG_LOCAL_PROTO, prefix, volume_id, gateway_id, fs_path, file_id, file_version, block_id, block_version );
      }
   }
   else {
      // remote data block
      ret = SG_CALLOC( char, strlen(prefix) + 1 + strlen(SG_DATA_PREFIX) + 1 + base_len );
      if( ret == NULL ) {
         return NULL;
      }
      
      sprintf(ret, "%s/%s/%" PRIu64 "%s.%" PRIX64 ".%" PRId64 "/%" PRIu64 ".%" PRId64,
                   prefix, SG_DATA_PREFIX, volume_id, fs_path, file_id, file_version, block_id, block_version );
   }

   return ret;  
}


/**
 * @brief Generate a locally-resolvable URL to a cached block 
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_block_data_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id, uint64_t file_id, int64_t file_version, uint64_t block_id, int64_t block_version ) {
   
   // file:// URL to a locally-hosted block in a locally-coordinated file
   char* fs_path = md_url_path_from_file_id( file_id );
   if( fs_path == NULL ) {
      return NULL;
   }
   
   char* ret = md_url_block_url( data_root, volume_id, gateway_id, fs_path, file_id, file_version, block_id, block_version, true, false );
   SG_safe_free( fs_path );
   return ret;
}


/**
 * @brief Generate a locally-resolvable URL to a write-staging block 
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_block_staging_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id, uint64_t file_id, int64_t file_version, uint64_t block_id, int64_t block_version ) {
   
   // file:// URL to a locally-hosted block in a locally-coordinated file
   char* fs_path = md_url_path_from_file_id( file_id );
   if( fs_path == NULL ) {
      return NULL;
   }
   
   char* ret = md_url_block_url( data_root, volume_id, gateway_id, fs_path, file_id, file_version, block_id, block_version, true, true );
   SG_safe_free( fs_path );
   return ret;
}


/**
 * @brief Generate a publicly-resolvable URL to a block in this UG
 *
 * Call md_url_block_url
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_public_block_url( char const* base_url, uint64_t volume_id, char const* fs_path, uint64_t file_id, int64_t file_version, uint64_t block_id, int64_t block_version ) {
   // http:// URL to a locally-hosted block in a locally-coordinated file
   return md_url_block_url( base_url, volume_id, 0, fs_path, file_id, file_version, block_id, block_version, false, false );
}

/**
 * @brief Generate a publicly-routable block URL, based on what gateway hosts it.
 * @retval 0 Success
 * @retval -EAGAN The gateway is currently unknown
 * @retval -ENOMEM Out of Memory
 */ 
int md_url_make_block_url( struct ms_client* ms, char const* fs_path, uint64_t gateway_id, uint64_t file_id, int64_t version, uint64_t block_id, int64_t block_version, char** url ) {
   
   uint64_t gateway_type = ms_client_get_gateway_type( ms, gateway_id );
   
   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      // unknown gateway---maybe try reloading the certs?
      SG_error("Unknown gateway %" PRIu64 "\n", gateway_id );
      return -EAGAIN;
   }
   
   uint64_t volume_id = ms_client_get_volume_id( ms );
   char* base_url = ms_client_get_gateway_url( ms, gateway_id );
   if( base_url == NULL ) {
      
      return -ENOMEM;
   }
   
   char* ret = md_url_block_url( base_url, volume_id, 0, fs_path, file_id, version, block_id, block_version, false, false );
   
   SG_safe_free( base_url );
   
   if( ret == NULL ) {
      return -ENOMEM;
   }
   
   *url = ret;
   
   return 0;
}


/**
 * @brief Generate a locally-resolvable URL to cached file data on this gateway
 * @note data_root must end in /
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_file_data_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id, uint64_t file_id, int64_t file_version ) {
   
   int base_len = 25 + 1 + 25 + 1 + 25 + 1 + 25 + 1 + 25 + 1 + 1;
   char* fs_path = md_url_path_from_file_id( file_id );
   if( fs_path == NULL ) {
      return NULL;
   }
   
   char* ret = SG_CALLOC( char, strlen(SG_LOCAL_PROTO) + 1 + strlen(data_root) + 1 + strlen(fs_path) + 1 + base_len + 1 );
   if( ret == NULL ) {
      SG_safe_free( fs_path );
      return NULL;
   }
   
   sprintf(ret, "%s%s%" PRIu64 "/%" PRIu64 "%s.%" PRIX64 ".%" PRId64,
                 SG_LOCAL_PROTO, data_root, volume_id, gateway_id, fs_path, file_id, file_version );

   SG_safe_free( fs_path );
   return ret;
}


/**
 * @brief Generate a locally-resolvable URL to staging file data on this gateway
 * @note data_root must end in /
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_file_staging_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id, uint64_t file_id, int64_t file_version ) {
   
   int base_len = 25 + 1 + 25 + 1 + 25 + 1 + 10 + 1 + 25 + 1 + 25 + 1 + 1;
   char* fs_path = md_url_path_from_file_id( file_id );
   if( fs_path == NULL ) {
      return NULL;
   }
   
   char* ret = SG_CALLOC( char, strlen(SG_LOCAL_PROTO) + 1 + strlen(fs_path) + 1 + strlen(data_root) + 1 + strlen(fs_path) + 1 + base_len + 1 );
   if( ret == NULL ) {
      SG_safe_free( fs_path );
      return NULL;
   }
   
   sprintf(ret, "%s%s%" PRIu64 "/staging/%" PRIu64 "%s.%" PRIX64 ".%" PRId64,
                 SG_LOCAL_PROTO, data_root, volume_id, gateway_id, fs_path, file_id, file_version );

   SG_safe_free( fs_path );
   return ret;
}


/**
 * @brief Generate a locally-resolvable URL to the gateway's cached data root
 * @note data_root must end in /
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_gateway_data_root_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id ) {

   char* ret = SG_CALLOC( char, strlen(SG_LOCAL_PROTO) + strlen(data_root) + 100 );
   if( ret == NULL ) {
      return NULL;
   }

   sprintf(ret, "%s%s%" PRIu64 "/%" PRIu64, SG_LOCAL_PROTO, data_root, volume_id, gateway_id );
   return ret;
}


/**
 * @brief Generate a locally-resolvable URL to the gateway's staging data root
 * @note data_root must end in /
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_local_gateway_staging_root_url( char const* data_root, uint64_t volume_id, uint64_t gateway_id ) {

   char* ret = SG_CALLOC( char, strlen(SG_LOCAL_PROTO) + strlen(data_root) + 110 );
   if( ret == NULL ) {
      return NULL;
   }

   sprintf(ret, "%s%sstaging/%" PRIu64 "/%" PRIu64, SG_LOCAL_PROTO, data_root, volume_id, gateway_id );
   return ret;
}


/**
 * @brief Manifest URL generator
 * @retval URL Success
 * @retval NULL Out of Memory
 */
char* md_url_public_manifest_url( char const* base_url, uint64_t volume_id, char const* fs_path, uint64_t file_id, int64_t version, struct timespec* ts ) {
   
   char* ret = SG_CALLOC( char, strlen(SG_DATA_PREFIX) + 1 + strlen(base_url) + 1 + strlen(fs_path) + 1 + 107 );
   if( ret == NULL ) {
      return NULL;
   }
   
   sprintf( ret, "%s%s/%" PRIu64 "%s.%" PRIX64 ".%" PRId64 "/manifest.%ld.%ld", base_url, SG_DATA_PREFIX, volume_id, fs_path, file_id, version, (long)ts->tv_sec, (long)ts->tv_nsec );
   return ret;
}


/**
 * @brief Generate a URL to an manifest, given its coordinator
 *
 * Automatically determine what kind of gateway hosts it.
 * @param url Point to a malloc'ed null-terminated string with the url
 * @retval 0 Success
 * @retval -EAGAIN The gateway is not known to us
 * @retval -ENOMEM Could not generate a URL
 */
int md_url_make_manifest_url( struct ms_client* ms, char const* fs_path, uint64_t gateway_id, uint64_t file_id, int64_t file_version, struct timespec* ts, char** url ) {
   
   // what kind of gateway?
   uint64_t gateway_type = ms_client_get_gateway_type( ms, gateway_id );

   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      // unknown gateway
      SG_error("Unknown Gateway %" PRIu64 "\n", gateway_id );
      return -EAGAIN;
   }
   
   char* base_url = ms_client_get_gateway_url( ms, gateway_id );
   if( base_url == NULL ) {
      return -ENOMEM;
   }
   
   uint64_t volume_id = ms_client_get_volume_id( ms );
   
   char* ret = md_url_public_manifest_url( base_url, volume_id, fs_path, file_id, file_version, ts );
   SG_safe_free( base_url );
   
   if( ret == NULL ) {
      
      return -ENOMEM;
   }
   
   *url = ret;
   return 0;
}


/**
 * @brief Generate a URL to a gateway's API server
 * @param[out] *url URL to the gateway
 * @retval 0 Success
 * @retval -EAGAIN There is no known gateway
 * @retval -ENOMEM Out of Memory
 */
int md_url_make_gateway_url( struct ms_client* ms, uint64_t gateway_id, char** url ) {
   
   // what kind of gateway?
   uint64_t gateway_type = ms_client_get_gateway_type( ms, gateway_id );

   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      // unknown gateway
      SG_error("Unknown Gateway %" PRIu64 "\n", gateway_id );
      return -EAGAIN;
   }
   
   char* base_url = ms_client_get_gateway_url( ms, gateway_id );
   if( base_url == NULL ) {
      return -ENOMEM;
   }
   
   *url = base_url;
   return 0;
}


/**
 * @brief Generate a getxattr URL to another gateway
 *
 * base_url/GETXATTR/volume_id/fs_path.file_id.file_version/xattr_name.xattr_nonce
 * @retval URL Success 
 * @retval NULL Out of Memory
 */
char* md_url_public_getxattr_url( char const* base_url, uint64_t volume_id, char const* fs_path, uint64_t file_id, int64_t file_version, char const* xattr_name, int64_t xattr_nonce ) {
   
   size_t len = strlen(base_url) + 1 + strlen(SG_GETXATTR_PREFIX) + 1 + 50 + 1 + strlen(fs_path) + 1 + 50 + 1 + 50 + 1 + strlen(xattr_name) + 1 + 50 + 1;
   char* url = SG_CALLOC( char, len );
   
   if( url == NULL ) {
      return NULL;
   }
   
   sprintf(url, "%s/%s/%" PRIu64 "/%s.%" PRIX64 ".%" PRId64 "/%s.%" PRId64, base_url, SG_GETXATTR_PREFIX, volume_id, fs_path, file_id, file_version, xattr_name, xattr_nonce );
   return url;
}


/**
 * @brief Generate a listxattr URL to another gateway
 *
 * base_url/LISTXATTR/volume_id/fs_path.file_id.file_version/xattr_nonce 
 * @retval URL Success 
 * @retval NULL Out of Memory
 */
char* md_url_public_listxattr_url( char const* base_url, uint64_t volume_id, char const* fs_path, uint64_t file_id, int64_t file_version, int64_t xattr_nonce ) {
   
   size_t len = strlen(base_url) + 1 + strlen(SG_LISTXATTR_PREFIX) + 1 + 50 + 1 + strlen(fs_path) + 1 + 50 + 1 + 50 + 1 + 50 + 1;
   char* url = SG_CALLOC( char, len );
   
   if( url == NULL ) {
      return NULL;
   }
   
   sprintf(url, "%s/%s/%" PRIu64 "/%s.%" PRIX64 ".%" PRId64 "/%" PRId64, base_url, SG_LISTXATTR_PREFIX, volume_id, fs_path, file_id, file_version, xattr_nonce );
   return url;
}

/**
 * @brief Generate a getxattr URL to a given gateway 
 * @param[out] *url URL to the gateway
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EAGAIN The gateway is not known to us
 */
int md_url_make_getxattr_url( struct ms_client* ms, char const* fs_path, uint64_t gateway_id, uint64_t file_id, int64_t file_version, char const* xattr_name, int64_t xattr_nonce, char** url ) {
   
   // what kind of gateway?
   uint64_t gateway_type = ms_client_get_gateway_type( ms, gateway_id );

   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      // unknown gateway
      SG_error("Unknown Gateway %" PRIu64 "\n", gateway_id );
      return -EAGAIN;
   }
   
   char* base_url = ms_client_get_gateway_url( ms, gateway_id );
   if( base_url == NULL ) {
      return -ENOMEM;
   }
   
   uint64_t volume_id = ms_client_get_volume_id( ms );
   
   char* ret = md_url_public_getxattr_url( base_url, volume_id, fs_path, file_id, file_version, xattr_name, xattr_nonce );
   SG_safe_free( base_url );
   
   if( ret == NULL ) {
      
      return -ENOMEM;
   }
   
   *url = ret;
   return 0;
}


/**
 * @brief Generate a listxattr URL to a given gateway
 * @param[out] *url URL to the gateway
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EAGAIN The gateway is not known to us
 */
int md_url_make_listxattr_url( struct ms_client* ms, char const* fs_path, uint64_t gateway_id, uint64_t file_id, int64_t file_version, int64_t xattr_nonce, char** url ) {
   
   // what kind of gateway?
   uint64_t gateway_type = ms_client_get_gateway_type( ms, gateway_id );

   if( gateway_type == SG_INVALID_GATEWAY_ID ) {
      // unknown gateway
      SG_error("Unknown Gateway %" PRIu64 "\n", gateway_id );
      return -EAGAIN;
   }
   
   char* base_url = ms_client_get_gateway_url( ms, gateway_id );
   if( base_url == NULL ) {
      return -ENOMEM;
   }
   
   uint64_t volume_id = ms_client_get_volume_id( ms );
   
   char* ret = md_url_public_listxattr_url( base_url, volume_id, fs_path, file_id, file_version, xattr_nonce );
   SG_safe_free( base_url );
   
   if( ret == NULL ) {
      
      return -ENOMEM;
   }
   
   *url = ret;
   return 0;
}

