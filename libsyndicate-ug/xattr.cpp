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

#include "consistency.h"
#include "core.h"
#include "xattr.h"


typedef ssize_t (*UG_xattr_get_handler_t)( struct fskit_core*, struct fskit_entry*, char const*, char*, size_t );
typedef int (*UG_xattr_set_handler_t)( struct fskit_core*, struct fskit_entry*, char const*, char const*, size_t, int );
typedef int (*UG_xattr_delete_handler_t)( struct fskit_core*, struct fskit_entry*, char const* );

struct UG_xattr_handler_t {
   char const* name;
   UG_xattr_get_handler_t get;
   UG_xattr_set_handler_t set;
   UG_xattr_delete_handler_t del;
};

struct UG_xattr_namespace_handler {
   char const* prefix;
   UG_xattr_get_handler_t get;
   UG_xattr_set_handler_t set;
   UG_xattr_delete_handler_t del;
};


// general purpose handlers...
int UG_xattr_set_undefined( struct fskit_core* core, struct fskit_entry* fent, char const* name, char const* buf, size_t buf_len, int flags ) {
   return -ENOTSUP;
}

int UG_xattr_del_undefined( struct fskit_core* core, struct fskit_entry* fent, char const* name ) {
   return -ENOTSUP;
}


// prototype special xattr handlers...
static ssize_t UG_xattr_get_cached_blocks( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len );
static ssize_t UG_xattr_get_cached_file_path( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len );
static ssize_t UG_xattr_get_coordinator( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len );
static ssize_t UG_xattr_get_read_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len );
static ssize_t UG_xattr_get_write_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len );

static int UG_xattr_set_read_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char const* buf, size_t buf_len, int flags );
static int UG_xattr_set_write_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char const* buf, size_t buf_len, int flags );

// default xattr handlers for built-in xattrs
static struct UG_xattr_handler_t xattr_handlers[] = {
   {UG_XATTR_COORDINATOR,        UG_xattr_get_coordinator,          UG_xattr_set_undefined,    UG_xattr_del_undefined},      // TODO: set coordinator by gateway name?
   {UG_XATTR_CACHED_BLOCKS,      UG_xattr_get_cached_blocks,        UG_xattr_set_undefined,    UG_xattr_del_undefined},
   {UG_XATTR_CACHED_FILE_PATH,   UG_xattr_get_cached_file_path,     UG_xattr_set_undefined,    UG_xattr_del_undefined},
   {UG_XATTR_READ_TTL,           UG_xattr_get_read_ttl,             UG_xattr_set_read_ttl,     UG_xattr_del_undefined},
   {UG_XATTR_WRITE_TTL,          UG_xattr_get_write_ttl,            UG_xattr_set_write_ttl,    UG_xattr_del_undefined},
   {NULL,                        NULL,                              NULL,                      NULL}
};


// look up an xattr handler for a given attribute name
// return a pointer to the handler on success
// return NULL if not found.
static struct UG_xattr_handler_t* UG_xattr_lookup_handler( char const* name ) {
   
   for( int i = 0; xattr_handlers[i].name != NULL; i++ ) {
      
      if( strcmp( xattr_handlers[i].name, name ) == 0 ) {
         
         return &xattr_handlers[i];
      }
   }
   
   return NULL;
}


// get size of all of the names of our xattrs
// always succeeds
size_t UG_xattr_builtin_len_all( void ) {
   
   size_t len = 0;
   
   for( int i = 0; xattr_handlers[i].name != NULL; i++ ) {
      
      len += strlen(xattr_handlers[i].name) + 1;        // include '\0'
   }
   
   return len;
}


// get concatenated names of all xattrs (delimited by '\0')
// fill in buf with the names, if it is long enough (buf_len)
// return the number of bytes copied on success
// return -ERANGE if the buffer is not big enough.
ssize_t UG_xattr_get_builtin_names( char* buf, size_t buf_len ) {
   
   size_t needed_len = UG_xattr_builtin_len_all();
   
   if( needed_len > buf_len ) {
      return -ERANGE;
   }
   
   ssize_t offset = 0;
   
   for( int i = 0; xattr_handlers[i].name != NULL; i++ ) {
      sprintf( buf + offset, "%s", xattr_handlers[i].name );
      
      offset += strlen(xattr_handlers[i].name);
      
      *(buf + offset) = '\0';
      
      offset ++;
   }
   
   return offset;
}

// get cached block vector, but as a string.
// string[i] == '1' if block i is cached.
// string[i] == '0' if block i is NOT cached.
// return the length of the buffer on success, and fill in *buf with the buffer if *buf is not NULL
// return -ENOMEM if OOM
// return -ERANGE if *buf is not NULL but buf_len is not long enough to hold the block vector
// NOTE: fent must be at least read-locked
static ssize_t UG_xattr_get_cached_blocks( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len) {
   
   struct local {
      
      // callback to fskit_entry_resolve_path_cls
      // *cls is a pointer to the null-terminated block vector we're filling in
      // returns 0 on success
      // return -ENOMEM on OOM
      static int xattr_stat_block( char const* block_path, void* cls ) {
         
         // NOTE: block_vector must be a null-terminated string, memset'ed to '0''s
         char* block_vector = (char*)cls;
         size_t num_blocks = strlen(block_vector);
         
         // which block is this?
         char* block_name = md_basename( block_path, NULL );
         if( block_name == NULL ) {
            
            return -ENOMEM;
         }
         
         // try to parse the ID
         int64_t id = 0;
         int rc = sscanf( block_name, "%" PRId64, &id );
         if( rc == 1 ) {
            
            // parsed!  This block is present
            if( (size_t)id < num_blocks ) {
               *(block_vector + id) = '1';
            }
         }
         
         free( block_name );
         
         return 0;
      }
   };
   
   struct SG_gateway* gateway = (struct SG_gateway*)fskit_core_get_user_data( core );
   struct ms_client* ms = SG_gateway_ms( gateway );
   uint64_t block_size = ms_client_get_volume_blocksize( ms );
   struct md_syndicate_conf* conf = SG_gateway_conf( gateway );
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   uint64_t volume_id = ms_client_get_volume_id( ms );
   
   off_t num_blocks = (fskit_entry_get_size( fent ) / block_size) + ((fskit_entry_get_size( fent ) % block_size) == 0 ? 0 : 1);
   
   if( (size_t)num_blocks >= buf_len + 1 ) {
      
      if( buf_len == 0 || buf == NULL ) {
         
         // size query
         return num_blocks + 1;         // NULL-terminated
      }
      else {
         
         // not enough space 
         return -ERANGE;
      }
   }
   
   char* cached_file_path = NULL;
   ssize_t rc = 0;
   
   char* cached_file_url = md_url_local_file_url( conf->data_root, volume_id, UG_inode_file_id( inode ), UG_inode_file_version( inode ) );
   if( cached_file_url == NULL ) {
      
      return -ENOMEM;
   }
   
   cached_file_path = SG_URL_LOCAL_PATH( cached_file_url );
   
   // enough space...
   if( buf_len > 0 ) {
      
      memset( buf, '0', buf_len );
      buf[buf_len - 1] = '\0';
   }
   
   rc = md_cache_file_blocks_apply( cached_file_path, local::xattr_stat_block, buf );
   
   free( cached_file_url );
   
   if( rc == 0 ) {
      
      rc = num_blocks;
   }
   else if( rc == -ENOENT ) {
      
      // no cached data--all 0's
      SG_debug("No data cached for %" PRIX64 ".%" PRId64 "\n", UG_inode_file_id( inode ), UG_inode_file_version( inode ) );
      
      memset( buf, '0', buf_len );
      buf[buf_len - 1] = '\0';
      
      rc = num_blocks;
   }
   
   return rc;
}


// get cached file path.
// fill it in in *buf
// return the length of the path (including the '\0') on success, and fill in *buf if it is not NULL
// return -ERANGE if the buf is not NULL and the buffer is not long enough 
// return -ENOMEM on OOM
// NOTE: fent must be read-locked
static ssize_t UG_xattr_get_cached_file_path( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len) {
   
   char* cached_file_path = NULL;
   size_t len = 0;
   
   struct SG_gateway* gateway = (struct SG_gateway*)fskit_core_get_user_data( core );
   struct ms_client* ms = SG_gateway_ms( gateway );
   struct md_syndicate_conf* conf = SG_gateway_conf( gateway );
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   uint64_t volume_id = ms_client_get_volume_id( ms );
   
   char* cached_file_url = md_url_local_file_url( conf->data_root, volume_id, UG_inode_file_id( inode ), UG_inode_file_version( inode ) );
   if( cached_file_url == NULL ) {
      
      return -ENOMEM;
   }

   cached_file_path = SG_URL_LOCAL_PATH( cached_file_url );
   
   len = strlen(cached_file_path);
   
   if( buf_len == 0 || buf == NULL ) {
      
      // size query
      free( cached_file_url );
      return len + 1;         // NULL-terminated
   }

   if( (size_t)len >= buf_len ) {
      
      // not enough space 
      free( cached_file_url );
      return -ERANGE;
   }
   
   // enough space...
   if( buf_len > 0 ) {
      
      strcpy( buf, cached_file_path );
   }
   
   free( cached_file_url );
   
   return len + 1;
}


// get the name of a coordinator of a file 
// return the length of the coordinator's name (plus the '\0'), and write it to *buf if buf is not NULL
// return -ERANGE if *buf is not NULL but not long enough 
// return -ENOATTR if the coordinator is not known to us (e.g. we're refreshing our cert bundle)
// return -ENOMEM if OOM
// NOTE: fent must be read-locked
static ssize_t UG_xattr_get_coordinator( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len ) {
   
   int rc = 0;
   char* gateway_name = NULL;
   
   struct SG_gateway* gateway = (struct SG_gateway*)fskit_core_get_user_data( core );
   struct ms_client* ms = SG_gateway_ms( gateway );
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   rc = ms_client_get_gateway_name( ms, UG_inode_coordinator_id( inode ), &gateway_name );
   
   if( rc != 0 || gateway_name == NULL ) {
      
      return -ENOATTR;
   }
   else {
      
      if( buf == NULL || buf_len == 0 ) {
         
         // query for size
         size_t len = strlen(gateway_name) + 1;
         free( gateway_name );
         
         return (ssize_t)len;
      }
      
      if( strlen(gateway_name) >= buf_len ) {
         
         // not big enough
         free( gateway_name );
         return -ERANGE;
      }
      
      size_t len = strlen(gateway_name) + 1;
      
      strcpy( buf, gateway_name );
      
      free( gateway_name );
      
      return (ssize_t)len;
   }
}


// get the read ttl as a string
// return the string length (plus '\0') on success, and write the string to *buf if buf is not NULL
// return -ERANGE if buf is not NULL but not long enough 
// NOTE: fent must be read-locked
static ssize_t UG_xattr_get_read_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len ) {
   
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   uint32_t read_ttl = UG_inode_max_read_freshness( inode );
   
   // how many bytes needed?
   ssize_t len = 2;
   if( read_ttl > 0 ) {
      len = (ssize_t)(log( (double)read_ttl )) + 1;
   }
   
   if( buf == NULL || buf_len == 0 ) {
      // size query
      return len;
   }
   
   if( (size_t)len > buf_len ) {
      // not big enough
      return -ERANGE;
   }
   
   sprintf( buf, "%u", read_ttl );
   
   return len;
}


// get the write ttl 
// return the string length (plus '\0') on success, and write the string to *buf if buf is not NULL
// return -ERANGE if buf is not NULL, but not long enough 
static ssize_t UG_xattr_get_write_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char* buf, size_t buf_len ) {
   
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   uint32_t write_ttl = UG_inode_max_write_freshness( inode );
   
   // how many bytes needed?
   ssize_t len = 2;
   if( write_ttl > 0 ) {
      
      len = (ssize_t)(log( (double)write_ttl )) + 1;
   }
   
   if( buf == NULL || buf_len == 0 ) {
      
      // size query
      return len;
   }
   
   if( (size_t)len > buf_len ) {
      
      // not big enough
      return -ERANGE;
   }
   
   sprintf( buf, "%u", write_ttl );
   
   return len;
}


// set the read ttl 
// return 0 on success
// return -EEXIST if the caller specified XATTR_CREATE--this attribute is built-in and always exists 
// return -EINVAL if we couldn't parse the buffer
// NOTE: fent must be write-locked
static int UG_xattr_set_read_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char const* buf, size_t buf_len, int flags ) {
   
   // this attribute always exists...
   if( (flags & XATTR_CREATE) ) {
      return -EEXIST;
   }
   
   // parse this
   struct UG_inode* inode = NULL;
   char* tmp = NULL;
   uint32_t read_ttl = (uint32_t)strtoll( buf, &tmp, 10 );
   
   if( tmp == buf || *tmp != '\0' ) {
      // invalid 
      return -EINVAL;
   }
   
   inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   UG_inode_set_max_read_freshness( inode, read_ttl );
   
   return 0;
}


// set the write ttl 
// return 0 on success 
// return -EEXIST if the caller specified XATTR_CREAT--this attribute is built-in and always exists 
// return -EINVAL if we couldn't parse the buffer 
// NOTE: fent must be write-locked
static int UG_xattr_set_write_ttl( struct fskit_core* core, struct fskit_entry* fent, char const* name, char const* buf, size_t buf_len, int flags ) {
   
   // this attribute always exists...
   if( (flags & XATTR_CREATE) ) {
      return -EEXIST;
   }
   
   // parse this
   struct UG_inode* inode = NULL;
   char* tmp = NULL;
   uint32_t write_ttl = (uint32_t)strtoll( buf, &tmp, 10 );
   
   if( tmp == buf || *tmp != '\0' ) {
      
      // invalid 
      return -EINVAL;
   }
   
   inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   UG_inode_set_max_write_freshness( inode, write_ttl );
   
   return 0;
}


// handle built-in getxattr
// return the length of the xattr value on success
// return 0 if not handled
// return the length of the xattr value on success
// return the length of the xattr value of *value is NULL, but the xattr is built-in
// return -ENOMEM on OOM
// return -ERANGE if the buf isn't big enough
// fent must be read-locked
static ssize_t UG_xattr_fgetxattr_builtin( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, char* value, size_t value_len ) {
    
   int rc = 0;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   struct UG_xattr_handler_t* handler = UG_xattr_lookup_handler( name );
   if( handler == NULL ) {
      // not handled
      return 0;
   } 

   rc = (*handler->get)( fs, fent, name, value, value_len );
   return rc;
}


// fgetxattr(2) implementation, for use in both the client, HTTP server, and fskit.
// handles local built-in xattrs and all remote xattrs.
// does not handle local non-built-in xattrs; defer to fskit for these.
// return length of the xattr on success
// return 0 if not handled (i.e. local request, and not a built-in xattr)
// return -ERANGE if the buffer is too small
// return -ENOENT if the entry doesn't exist
// return -EACCES if we don't have permission to read
// return -EAGAIN if we're acting on stale data, and should try again
// return -ETIMEDOUT if the xattr is remote, and could not be completed on time
// return -EREMOTEIO on remote I/O error
// return -ENOATTR if the attribute doesn't exist
// NOTE: fent must be read-locked
ssize_t UG_xattr_fgetxattr_ex( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, char* value, size_t size, bool query_remote ) {

   int rc = 0;
   struct UG_inode* inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   uint64_t coordinator_id = UG_inode_coordinator_id( inode );
   uint64_t file_id = UG_inode_file_id( inode );
   int64_t file_version = UG_inode_file_version( inode );
   int64_t xattr_nonce = UG_inode_xattr_nonce( inode );

   char* value_buf = NULL;
   size_t xattr_buf_len = 0;
   
   if( coordinator_id == SG_gateway_id( gateway ) ) {
       // local (built-in or otherwise)
       rc = UG_xattr_fgetxattr_builtin( gateway, path, fent, name, value, size );
       return rc;
   }
   else if( query_remote ) { 
      
       // go get the xattr remotely
       rc = SG_client_getxattr( gateway, coordinator_id, path, file_id, file_version, name, xattr_nonce, &value_buf, &xattr_buf_len );
       if( rc != 0 ) {
       
           SG_error("SG_client_getxattr('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, file_id, file_version, xattr_nonce, name, rc );
       }
   
       if( value != NULL ) {
       
          if( xattr_buf_len <= size ) {
             memcpy( value, value_buf, xattr_buf_len );
             rc = xattr_buf_len;
          }
          else {
          
             rc = -ERANGE;
          }
       }
       else {
      
          rc = xattr_buf_len;
       }
       SG_safe_free( value_buf );
   }
   else {
      rc = -ESTALE;
   }

   if( rc < 0 && rc != -EACCES && rc != -ENOENT && rc != -ETIMEDOUT && rc != -ENOMEM && rc != -EAGAIN && rc != -ERANGE && rc != -ENOATTR && rc != -ESTALE ) {
      rc = -EREMOTEIO;
   }
   return rc;
}

ssize_t UG_xattr_fgetxattr( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, char* value, size_t value_len ) {
   return UG_xattr_fgetxattr_ex( gateway, path, fent, name, value, value_len, true );
}

// getxattr(2) for the HTTP server and client
// handles all xattrs--local and remote, builtin and non-built-in.
// return the length of the xattr value on success
// return the length of the xattr value if *value is NULL, but we were able to get the xattr
// return -ENOMEM on OOM 
// return -ENOENT if the file doesn't exist
// return -EACCES if we're not allowed to read the file or the attribute
// return -ETIMEDOUT if the transfer could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the remote host couldn't process the request 
ssize_t UG_xattr_getxattr_ex( struct SG_gateway* gateway, char const* path, char const *name, char *value, size_t size, uint64_t owner_id, uint64_t volume_id, bool query_remote ) {
   
   int rc = 0;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   
   // revalidate...
   rc = UG_consistency_path_ensure_fresh( gateway, path );
   if( rc != 0 ) {
      
      return rc;
   }
   
   // look up...
   struct fskit_entry* fent = fskit_entry_resolve_path( fs, path, owner_id, volume_id, false, &rc );
   if( fent == NULL ) {
      
      return rc;
   }

   // get the xattr
   rc = UG_xattr_fgetxattr_ex( gateway, path, fent, name, value, size, query_remote );
   if( rc == 0 ) {

      // not built-in 
      // get from inode directly
      rc = fskit_xattr_fgetxattr( fs, fent, name, value, size );
   }
   fskit_entry_unlock( fent );
   return rc;
}

ssize_t UG_xattr_getxattr( struct SG_gateway* gateway, char const* path, char const* name, char* value, size_t size, uint64_t owner_id, uint64_t volume_id ) {
   return UG_xattr_getxattr_ex( gateway, path, name, value, size, owner_id, volume_id, true );
}


// handle built-in setxattr
// return 0 if handled
// return 1 if not handled
// return -ENOMEM on OOM
// fent must be read-locked
static ssize_t UG_xattr_fsetxattr_builtin( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, char const* value, size_t value_len, int flags ) {
    
   int rc = 0;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   struct UG_xattr_handler_t* handler = UG_xattr_lookup_handler( name );
   if( handler == NULL || handler->set == UG_xattr_set_undefined ) {
      // not handled
      return 1;
   } 

   rc = (*handler->set)( fs, fent, name, value, value_len, flags );
   return rc;
}


// local setxattr, for when we're the coordinator of the file.
// return 0 on success 
// return -ENOMEM on OOM 
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// NOTE: inode->entry must be write-locked
static int UG_xattr_setxattr_local( struct SG_gateway* gateway, char const* path, struct UG_inode* inode, char const* name, char const* value, size_t value_len, int flags ) {
    
    int rc = 0;
    struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
    struct fskit_core* fs = UG_state_fs( ug );
    struct ms_client* ms = SG_gateway_ms( gateway );
    struct md_entry inode_data;
    int64_t cur_xattr_nonce = 0;
    unsigned char xattr_hash[ SHA256_DIGEST_LENGTH ];
    
    memset( &inode_data, 0, sizeof(struct md_entry) );
    
    // get inode info
    rc = UG_inode_export( &inode_data, inode, 0 );
    if( rc != 0 ) {

        return rc;
    }

    // get new xattr hash, for the *next* nonce value 
    cur_xattr_nonce = UG_inode_xattr_nonce( inode );
    UG_inode_set_xattr_nonce( inode, cur_xattr_nonce + 1 );
    rc = UG_inode_export_xattr_hash( fs, SG_gateway_id( gateway ), inode, xattr_hash );
    UG_inode_set_xattr_nonce( inode, cur_xattr_nonce );

    if( rc != 0 ) {
        
        md_entry_free( &inode_data );
        return rc;
    }

    // propagate new xattr hash
    inode_data.xattr_hash = xattr_hash;
    inode_data.xattr_nonce = cur_xattr_nonce + 1;
    
    // put on the MS...
    rc = ms_client_putxattr( ms, &inode_data, name, value, value_len, xattr_hash );
    
    inode_data.xattr_hash = NULL;       // NOTE: don't free this 
    
    if( rc != 0 ) {
        
        SG_error("ms_client_putxattr('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, inode_data.file_id, inode_data.version, inode_data.xattr_nonce, name, rc );
    }
    
    // propagate new xattr info from MS
    UG_inode_set_xattr_nonce( inode, inode_data.xattr_nonce );
    UG_inode_set_ms_xattr_hash( inode, xattr_hash );

    md_entry_free( &inode_data );
    
    return rc;
}


// remote setxattr, for when we're NOT the coordinator of the file 
// return 0 on success 
// return -ENOMEM on OOM 
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// NOTE: inode->entry must be at least read-locked
static int UG_xattr_setxattr_remote( struct SG_gateway* gateway, char const* path, struct UG_inode* inode, char const* name, char const* value, size_t value_len, int flags ) {
    
    int rc = 0;
    SG_messages::Request request;
    SG_messages::Reply reply;
    struct SG_request_data reqdat;
    
    uint64_t file_id = UG_inode_file_id( inode );
    uint64_t coordinator_id = UG_inode_coordinator_id( inode );
    int64_t file_version = UG_inode_file_version( inode );
    int64_t xattr_nonce = UG_inode_xattr_nonce( inode );
    
    rc = SG_request_data_init_setxattr( gateway, path, file_id, file_version, xattr_nonce, name, value, value_len, &reqdat );
    if( rc != 0 ) {
        return rc;
    }
   
    rc = SG_client_request_SETXATTR_setup( gateway, &request, &reqdat, UG_inode_coordinator_id( inode ), name, value, value_len, flags );
    if( rc != 0 ) {
        
        SG_request_data_free( &reqdat );
        return rc;
    }
    
    rc = SG_client_request_send( gateway, coordinator_id, &request, NULL, &reply );
    SG_request_data_free( &reqdat );
    
    if( rc != 0 ) {
        
        SG_error("SG_client_send_request(SETXATTR %" PRIu64 ", '%s') rc = %d\n", coordinator_id, name, rc );
        return rc;
    }
    
    // success!
    return rc;
}


// fsetxattr implementation, used by the client, the HTTP server, and fskit
// handles both remote and local xattrs, as well as built-in and non-built-in. 
// return 0 if handled
// return 1 if not handled
// return -ENOMEM on OOM
// return -EPERM if this gateway is anonymous
// return -ETIMEDOUT on timeout
// return -EREMOTEIO on failure to process remotely 
// return -EAGAIN if we're acting on stale data
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// fent must be write-locked
int UG_xattr_fsetxattr( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, char const* value, size_t size, int flags ) {

   int rc = 0;
   struct UG_inode* inode = NULL;

   inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   uint64_t coordinator_id = UG_inode_coordinator_id( inode );
   uint64_t file_id = UG_inode_file_id( inode );
   int64_t file_version = UG_inode_file_version( inode );
   int64_t xattr_nonce = UG_inode_xattr_nonce( inode );
    
   if( SG_gateway_id( gateway ) == SG_GATEWAY_ANON ) {
      return -EPERM;
   }

   // if we're the coordinator, then preserve old xattr, in case we have to replace it on failure 
   if( coordinator_id == SG_gateway_id( gateway ) ) {
       
       // built-in?
       rc = UG_xattr_fsetxattr_builtin( gateway, path, fent, name, value, size, flags );
       if( rc <= 0 ) {
          // handled-built-in or error
          if( rc < 0 ) {
             SG_error("UG_xattr_fsetxattr_builtin(%s, '%s') rc = %d\n", path, name, rc);
          }
          else {
             SG_debug("UG_xattr_fsetxattr_builtin(%s, '%s'): handled\n", path, name );
          }

          goto UG_xattr_fsetxattr_out;
       }

       // not handled---set the xattr on the MS, and tell caller to do the set locally
       rc = UG_xattr_setxattr_local( gateway, path, inode, name, value, size, flags );
       if( rc < 0 ) {
           SG_error("UG_xattr_setxattr_local('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, file_id, file_version, xattr_nonce, name, rc );
           goto UG_xattr_fsetxattr_out;
       }
        
       rc = 1;
   }
   else {
       
       // if we're not the coordinator, send the xattr to the coordinator 
       rc = UG_xattr_setxattr_remote( gateway, path, inode, name, value, size, flags );
       if( rc != 0 ) {
           SG_error("UG_xattr_setxattr_remote('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, file_id, file_version, xattr_nonce, name, rc );
           goto UG_xattr_fsetxattr_out;
       }

       rc = 1;
   }
   

UG_xattr_fsetxattr_out:
   if( rc < 0 && rc != -EACCES && rc != -ENOENT && rc != -ETIMEDOUT && rc != -ENOMEM && rc != -EAGAIN && rc != -ENOATTR && rc != -EEXIST ) {
      rc = -EREMOTEIO;
   }

   return rc;

} 


// setxattr(2)
// works for the HTTP server and client, but not for fskit
// return -ENOMEM on OOM 
// return -ENOENT if the file doesn't exist
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// return -EACCES if we're not allowed to write to the file
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// return -ESTALE if ask_remote is False and we're not the coordinator
int UG_xattr_setxattr_ex( struct SG_gateway* gateway, char const* path, char const *name, char const *value, size_t size, int flags, uint64_t user, uint64_t volume, bool query_remote ) {
   
   int rc = 0;
   struct fskit_entry* fent = NULL;
   struct UG_inode* inode = NULL;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   
   if( SG_gateway_id( gateway ) == SG_GATEWAY_ANON ) {
      return -EPERM;
   }
   
   rc = UG_consistency_path_ensure_fresh( gateway, path );
   if( rc != 0 ) {
      
      return rc;
   }
   
   fent = fskit_entry_resolve_path( fs, path, user, volume, true, &rc );
   if( fent == NULL ) {
      
      return rc;
   }

   inode = (struct UG_inode*)fskit_entry_get_user_data(fent);
   if( !query_remote && UG_inode_coordinator_id(inode) != SG_gateway_id(gateway) ) {

      fskit_entry_unlock( fent );
      return -ESTALE;
   }
   
   rc = UG_xattr_fsetxattr( gateway, path, fent, name, value, size, flags );
   if( rc > 0 ) {
      // sync'ed with the MS.  Pass along to fskit.
      rc = fskit_xattr_fsetxattr( fs, fent, name, value, size, flags );
   }

   fskit_entry_unlock( fent );
   return rc;
}

int UG_xattr_setxattr( struct SG_gateway* gateway, char const* path, char const *name, char const *value, size_t size, int flags, uint64_t user, uint64_t volume ) {
   return UG_xattr_setxattr_ex( gateway, path, name, value, size, flags, user, volume, true );
}


// handle built-in listxattr
// return the length of the listing on success, or if *buf is NULL or buf_len is 0
// return -ENOMEM on OOM
// return -ERANGE if the buf isn't big enough
// fent must be read-locked
static ssize_t UG_xattr_flistxattr_builtin( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char* buf, size_t buf_len ) {
    
   size_t builtin_len = UG_xattr_builtin_len_all();
   
   if( buf == NULL || buf_len == 0 ) {
      return builtin_len;
   }

   if( buf_len < builtin_len ) {
      return -ERANGE;
   }

   UG_xattr_get_builtin_names( buf, buf_len );
   return builtin_len;
}


// Implementation of flistxattr(2) for client, HTTP server, and fskit
// return the length of the listing on success
// return -ENOMEM on OOM
// return -ERANGE if the buffer isn't big enough
// return -EACCES if we can't read the entry
// return -ENOENT if the entry doesn't exist
// return -ETIMEDOUT on network timeout
// return -EREMOTEIO on remote host processing failure
// return -ESTALE if the query_remote is False and we're not the coordinator
// fent must be read-locked
ssize_t UG_xattr_flistxattr_ex( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char* buf, size_t buf_len, bool query_remote ) {

   int rc = 0;
   
   uint64_t file_id = 0;
   int64_t file_version = 0;
   int64_t xattr_nonce = 0;
   uint64_t coordinator_id = 0;
   struct UG_inode* inode = NULL;
   char* list_buf = NULL;
   size_t list_buf_len = 0;
   int builtin_len = 0;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls(gateway);
   struct fskit_core* fs = UG_state_fs(ug);
   char* buf_off = NULL;

   inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   file_id = UG_inode_file_id( inode );
   file_version = UG_inode_file_version( inode );
   xattr_nonce = UG_inode_xattr_nonce( inode );
   coordinator_id = UG_inode_coordinator_id( inode );
   
   if( coordinator_id == SG_gateway_id( gateway ) ) {
       
       // provide built-in xattrs
       rc = UG_xattr_flistxattr_builtin( gateway, path, fent, buf, buf_len );
       if( rc < 0 ) {
          SG_error("UG_xattr_flistxattr_builtin(%s) rc = %d\n", path, rc );
          goto UG_xattr_flistxattr_out;
       }

       SG_debug("builtin xattrs: %d bytes\n", rc );

       // merge
       builtin_len = rc;

       // if buf is NULL, then pass NULL to flistxattr
       if( buf != NULL ) {
          buf_off = buf + builtin_len;
       }
       else {
          buf_off = NULL;
       }

       rc = fskit_xattr_flistxattr( fs, fent, buf_off, buf_len - builtin_len );
       if( rc < 0 ) {
          SG_error("fskit_xattr_flistxattr(%s) rc = %d\n", path, rc );
          goto UG_xattr_flistxattr_out;
       }

       SG_debug("fskit xattr: %d bytes\n", rc );

       rc += builtin_len;
   }
   else if( query_remote ) {

       // ask the coordinator 
       rc = SG_client_listxattrs( gateway, coordinator_id, path, file_id, file_version, xattr_nonce, &list_buf, &list_buf_len );
       if( rc < 0 ) {
           SG_error("SG_client_listxattrs('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ")) rc = %d\n", path, file_id, file_version, xattr_nonce, rc );
       }
       else {

           if( buf_len > 0 && buf_len < list_buf_len ) {
               rc = -ERANGE;
           }
           else {
               if( buf != NULL ) {
                   memcpy( buf, list_buf, list_buf_len );
               }
               rc = list_buf_len;
           }

           SG_safe_free( list_buf );
       }
   } 
   else {

      rc = -ESTALE;
   }

UG_xattr_flistxattr_out:

   if( rc < 0 && rc != -EACCES && rc != -ENOENT && rc != -ETIMEDOUT && rc != -ENOMEM && rc != -ERANGE && rc != -EAGAIN && rc != -ESTALE ) {
      rc = -EREMOTEIO;
   }

   return rc;
}

ssize_t UG_xattr_flistxattr( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char* buf, size_t buf_len ) {
   return UG_xattr_flistxattr_ex( gateway, path, fent, buf, buf_len, true );
}


// listxattr(2)--get back a list of xattrs from the MS (for the client and HTTP server)
// return the number of bytes copied on success, and fill in *list (if non-null) with \0-separated names for xattrs (up to size bytes)
// return the number of bytes needed for *list, if *list is NULL
// return -ENOMEM on OOM 
// return -ENOENT if the file doesn't exist
// return -ERANGE if list is not NULL, but too small
// return -EACCES if we're not allowed to write to the file
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// return -ESTALE if ask_remote is False, and we're not the coordinator
ssize_t UG_xattr_listxattr_ex( struct SG_gateway* gateway, char const* path, char *list, size_t size, uint64_t user, uint64_t volume, bool query_remote ) {
   
   int rc = 0;
   
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   struct fskit_entry* fent = NULL;
   struct UG_inode* inode = NULL;
      
   rc = UG_consistency_path_ensure_fresh( gateway, path );
   if( rc != 0 ) {
      
      SG_error("UG_consistency_path_ensure_fresh('%s') rc = %d\n", path, rc );
      return rc;
   }
   
   fent = fskit_entry_resolve_path( fs, path, user, volume, false, &rc );
   if( fent == NULL ) {
      return rc;
   }

   inode = (struct UG_inode*)fskit_entry_get_user_data(fent);
   if( !query_remote && UG_inode_coordinator_id(inode) != SG_gateway_id(gateway) ) {

      fskit_entry_unlock( fent );
      return -ESTALE;
   }

   rc = UG_xattr_flistxattr_ex( gateway, path, fent, list, size, query_remote );
   fskit_entry_unlock( fent );
   return rc;
}

ssize_t UG_xattr_listxattr( struct SG_gateway* gateway, char const* path, char *list, size_t size, uint64_t user, uint64_t volume ) {
   return UG_xattr_listxattr_ex( gateway, path, list, size, user, volume, true );
}


// handle built-in removexattr
// return 0 on success
// return 1 if not handled
// return the length of the xattr value on success
// return the length of the xattr value of *value is NULL, but the xattr is built-in
// return -ENOMEM on OOM
// return -ENOENT if the file doesn't exist
// return -EACCES if we're not allowed to read the file or attribute
// fent must be read-locked
static ssize_t UG_xattr_fremovexattr_builtin( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name ) {
    
   int rc = 0;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   struct UG_xattr_handler_t* handler = UG_xattr_lookup_handler( name );
   if( handler == NULL || handler->del == UG_xattr_del_undefined ) {
      // not handled
      return 1;
   } 

   rc = (*handler->del)( fs, fent, name );
   return rc;
}


// local removexattr, for when we're the coordinator of the file.
// NOTE: the xattr must have already been removed from the file
// return 0 on success 
// return -ENOMEM on OOM 
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// NOTE: inode->entry must be at least read-locked
static int UG_xattr_removexattr_local( struct SG_gateway* gateway, char const* path, struct UG_inode* inode, char const* name ) {
    
    int rc = 0;
    struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
    struct fskit_core* fs = UG_state_fs( ug );
    struct ms_client* ms = SG_gateway_ms( gateway );
    struct md_entry inode_data;
    int64_t cur_xattr_nonce = 0;
    unsigned char xattr_hash[ SHA256_DIGEST_LENGTH ];
    
    memset( &inode_data, 0, sizeof(struct md_entry) );
    
    // get inode info
    rc = UG_inode_export( &inode_data, inode, 0 );
    if( rc != 0 ) {

        return rc;
    }

    // get new xattr hash, for the *next* nonce value 
    cur_xattr_nonce = UG_inode_xattr_nonce( inode );
    UG_inode_set_xattr_nonce( inode, cur_xattr_nonce + 1 );
    rc = UG_inode_export_xattr_hash( fs, SG_gateway_id( gateway ), inode, xattr_hash );
    UG_inode_set_xattr_nonce( inode, cur_xattr_nonce );

    if( rc != 0 ) {
        
        md_entry_free( &inode_data );
        return rc;
    }

    // propagate new xattr hash
    inode_data.xattr_hash = xattr_hash;
    inode_data.xattr_nonce = cur_xattr_nonce + 1;
    
    // put on the MS...
    rc = ms_client_removexattr( ms, &inode_data, name, xattr_hash );
    
    inode_data.xattr_hash = NULL;       // NOTE: don't free this 
    
    if( rc != 0 ) {
        
        SG_error("ms_client_removexattr('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, inode_data.file_id, inode_data.version, inode_data.xattr_nonce, name, rc );
    }
    
    // propagate new xattr info from MS
    UG_inode_set_xattr_nonce( inode, inode_data.xattr_nonce );
    UG_inode_set_ms_xattr_hash( inode, xattr_hash );

    md_entry_free( &inode_data );
    
    return rc;
}


// remote removexattr, for when we're NOT the coordinator of the file 
// return 0 on success 
// return -ENOMEM on OOM 
// return -EEXIST if the XATTR_CREATE flag was set but the attribute existed 
// return -ENOATTR if the XATTR_REPLACE flag was set but the attribute did not exist
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// NOTE: inode->entry must be at least read-locked
static int UG_xattr_removexattr_remote( struct SG_gateway* gateway, char const* path, struct UG_inode* inode, char const* name ) {
    
    int rc = 0;
    SG_messages::Request request;
    SG_messages::Reply reply;
    struct SG_request_data reqdat;
    
    uint64_t file_id = UG_inode_file_id( inode );
    uint64_t coordinator_id = UG_inode_coordinator_id( inode );
    int64_t file_version = UG_inode_file_version( inode );
    int64_t xattr_nonce = UG_inode_xattr_nonce( inode );
    
    rc = SG_request_data_init_removexattr( gateway, path, file_id, file_version, xattr_nonce, name, &reqdat );
    if( rc != 0 ) {
        SG_error("SG_request_data_init_removexattr('%s', '%s') rc = %d\n", path, name, rc );
        return rc;
    }
    
    rc = SG_client_request_REMOVEXATTR_setup( gateway, &request, &reqdat, UG_inode_coordinator_id( inode ), name );
    if( rc != 0 ) {
        
        SG_request_data_free( &reqdat );
        SG_error("SG_request_REMOVEXATTR_setup('%s', '%s') rc = %d\n", path, name, rc );
        return rc;
    }
    
    rc = SG_client_request_send( gateway, coordinator_id, &request, NULL, &reply );
    SG_request_data_free( &reqdat );
    
    if( rc != 0 ) {
        
        SG_error("SG_client_send_request(REMOVEXATTR %" PRIu64 ", '%s') rc = %d\n", coordinator_id, name, rc );
        return rc;
    }
    
    // success!
    return rc;
}


// Implementation of fremovexattr for the client, HTTP server, and fskit
// return 0 on success
// return 1 if the xattr was removed, but was not a built-in one (i.e. fskit has to handle it too)
// return -ENOMEM on OOM
// return -EPERM if this is an anonymous gateway
// return -ERANGE if the buffer isn't big enough
// return -EACCES if we can't write to this file
// return -ENOENT if the file doesn't exist
// return -ETIMEDOUT if the transfer could not complete in time
// return -EAGAIN if we're acting on stale data
// return -ENOATTR if the attribute doesn't exist
// return -EREMOTEIO if the the remote servers couldn't process the request
// return -ESTALE if query_remote is False and we're not the coordinator
// fent must be write-locked 
int UG_xattr_fremovexattr_ex( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name, bool query_remote ) {

   int rc = 0;
   struct UG_inode* inode = NULL;
 
   if( SG_gateway_id( gateway ) == SG_GATEWAY_ANON ) {
      return -EPERM;
   }

   // not a built-in
   inode = (struct UG_inode*)fskit_entry_get_user_data( fent );
   
   uint64_t coordinator_id = UG_inode_coordinator_id( inode );
   uint64_t file_id = UG_inode_file_id( inode );
   int64_t file_version = UG_inode_file_version( inode );
   int64_t xattr_nonce = UG_inode_xattr_nonce( inode );
   
   if( coordinator_id == SG_gateway_id( gateway ) ) {
      // built-in?
      rc = UG_xattr_fremovexattr_builtin( gateway, path, fent, name );
      if( rc <= 0 ) {
         if( rc < 0 ) {
            SG_error("UG_xattr_fremovexattr_builtin(%s, '%s') rc = %d\n", path, name, rc );
         }
         else {
            SG_debug("UG_xattr_fremovexattr_builtin(%s, '%s') handled\n", path, name );
         }

         // handled or error 
         goto UG_xattr_fremovexattr_out;
      }

      // not built-in. remove from MS
      rc = UG_xattr_removexattr_local( gateway, path, inode, name );
      if( rc != 0 ) {
           
          SG_error("UG_xattr_removexattr_local('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, file_id, file_version, xattr_nonce, name, rc );
          goto UG_xattr_fremovexattr_out;
      }

      rc = 1;
   }
   else if( query_remote ) {
       
       // if we're not the coordinator, send the remove request to the coordinator
       SG_debug("Ask %" PRIu64 " to remove '%s'\n", coordinator_id, name ); 
       rc = UG_xattr_removexattr_remote( gateway, path, inode, name );
       if( rc != 0 ) {
           
           SG_error("UG_xattr_removexattr_remote('%s' (%" PRIX64 ".%" PRId64 ".%" PRId64 ") '%s') rc = %d\n", path, file_id, file_version, xattr_nonce, name, rc );
           goto UG_xattr_fremovexattr_out;
       }

       rc = 1;
   }
   else {

      rc = -ESTALE;
   }

UG_xattr_fremovexattr_out:
   if( rc < 0 && rc != -EACCES && rc != -ENOENT && rc != -ETIMEDOUT && rc != -EAGAIN && rc != -ENOMEM && rc != -ENOATTR && rc != -ESTALE ) {
      rc = -EREMOTEIO;
   }

   return rc;
}

int UG_xattr_fremovexattr( struct SG_gateway* gateway, char const* path, struct fskit_entry* fent, char const* name ) {
   return UG_xattr_fremovexattr_ex( gateway, path, fent, name, true );
}


// removexattr(2)--delete an xattr on the MS and locally
// return 0 on success
// return -ENOMEM on OOM 
// return -EPERM if this is an anonymous gateway
// return -ENOENT if the file doesn't exist
// return -ERANGE if list is not NULL, but too small
// return -EACCES if we're not allowed to write to the file
// return -ETIMEDOUT if the tranfser could not complete in time 
// return -EAGAIN if we were signaled to retry the request 
// return -EREMOTEIO if the HTTP error is >= 500 
// return -EPROTO on HTTP 400-level error
// return -ESTALE if query_remote is False and we're not the coordinator
int UG_xattr_removexattr_ex( struct SG_gateway* gateway, char const* path, char const *name, uint64_t user, uint64_t volume, bool query_remote ) {
   
   int rc = 0;
   struct fskit_entry* fent = NULL;
   struct UG_state* ug = (struct UG_state*)SG_gateway_cls( gateway );
   struct fskit_core* fs = UG_state_fs( ug );
   
   if( SG_gateway_id( gateway ) == SG_GATEWAY_ANON ) {
      return -EPERM;
   }
   
   rc = UG_consistency_path_ensure_fresh( gateway, path );
   if( rc != 0 ) {
      
      return rc;
   }
   
   fent = fskit_entry_resolve_path( fs, path, user, volume, true, &rc );
   if( fent == NULL ) {
      
      return rc;
   }

   rc = UG_xattr_fremovexattr_ex( gateway, path, fent, name, query_remote );
   if( rc > 0 ) {
      // pass along to fskit 
      rc = fskit_xattr_fremovexattr( fs, fent, name );
      if( rc == -ENOATTR ) {
         // not a problem if UG_xattr_fremovexattr_ex succeeded
         rc = 0;
      }
   }

   fskit_entry_unlock( fent );
   return rc;
}

int UG_xattr_removexattr( struct SG_gateway* gateway, char const* path, char const* name, uint64_t user, uint64_t volume ) {
   return UG_xattr_removexattr_ex( gateway, path, name, user, volume, true );
}

