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

#include "libsyndicate/ms/xattr.h"
#include "libsyndicate/ms/file.h"
#include "libsyndicate/ms/url.h"

#include <endian.h>

// borrowed from https://github.com/stevengj/nlopt/blob/master/util/qsort_r.c
// the algorithms swap() and nlopt_qsort_r() are subject to the following copyright notice:

/* copyright 2007-2014 MIT
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

/* swap size bytes between a_ and b_ */
static void swap(void *a_, void *b_, size_t size)
{
     if (a_ == b_) return;
     {
          size_t i, nlong = size / sizeof(long);
          long *a = (long *) a_, *b = (long *) b_;
          for (i = 0; i < nlong; ++i) {
               long c = a[i];
               a[i] = b[i];
               b[i] = c;
          }
	  a_ = (void*) (a + nlong);
	  b_ = (void*) (b + nlong);
     }
     {
          size_t i;
          char *a = (char *) a_, *b = (char *) b_;
          size = size % sizeof(long);
          for (i = 0; i < size; ++i) {
               char c = a[i];
               a[i] = b[i];
               b[i] = c;
          }
     }
}

void nlopt_qsort_r(void *base_, size_t nmemb, size_t size, void *thunk,
		   int (*compar)(void *, const void *, const void *))
{
     char *base = (char *) base_;
     if (nmemb < 10) { /* use O(nmemb^2) algorithm for small enough nmemb */
	  size_t i, j;
	  for (i = 0; i+1 < nmemb; ++i)
	       for (j = i+1; j < nmemb; ++j)
		    if (compar(thunk, base+i*size, base+j*size) > 0)
			 swap(base+i*size, base+j*size, size);
     }
     else {
	  size_t i, pivot, npart;
	  /* pick median of first/middle/last elements as pivot */
	  {
	       const char *a = base, *b = base + (nmemb/2)*size, 
		    *c = base + (nmemb-1)*size;
	       pivot = compar(thunk,a,b) < 0
		    ? (compar(thunk,b,c) < 0 ? nmemb/2 :
		       (compar(thunk,a,c) < 0 ? nmemb-1 : 0))
		    : (compar(thunk,a,c) < 0 ? 0 :
		       (compar(thunk,b,c) < 0 ? nmemb-1 : nmemb/2));
	  }
	  /* partition array */
	  swap(base + pivot*size, base + (nmemb-1) * size, size);
	  pivot = (nmemb - 1) * size;
	  for (i = npart = 0; i < nmemb-1; ++i)
	       if (compar(thunk, base+i*size, base+pivot) <= 0)
		    swap(base+i*size, base+(npart++)*size, size);
	  swap(base+npart*size, base+pivot, size);
	  /* recursive sort of two partitions */
	  nlopt_qsort_r(base, npart, size, thunk, compar);
	  npart++; /* don't need to sort pivot */
	  nlopt_qsort_r(base+npart*size, nmemb-npart, size, thunk, compar);
     }
}

// sort comparator 
// xattr_i1 and xattr_i2 are pointers to integers 
// cls is the list of xattr names
// the effect of this method is to order the integer array by xattr name.
static int ms_client_xattr_compar( void* cls, const void* xattr_i1, const void* xattr_i2 ) {
   
   char** xattr_names = (char**)cls;
   int* i1 = (int*)xattr_i1;
   int* i2 = (int*)xattr_i2;
   
   return strcmp( xattr_names[*i1], xattr_names[*i2] );
}

// find the hash over a file's xattrs and metadata.
// xattr_names and xattr_values should be the same length, and should be null-terminated
// or, xattr_names and xattr_values and xattr_lengths can all be NULL
// the hash incorporates the volume ID, file ID, xattr nonce, xattr names, and xattr values, in that order.
// the numbers are converted to network byte order first.
// return 0 on success 
// return -ENOMEM on OOM 
// return -EINVAL if the number of xattr names and values doesn't match, or if some but not all of (xattr_names, xattr_values, xattr_lengths) are NULL
int ms_client_xattr_hash( unsigned char* sha256_buf, uint64_t volume_id, uint64_t file_id, int64_t xattr_nonce, char** xattr_names, char** xattr_values, size_t* xattr_lengths ) {
   
   uint64_t volume_id_nb = htobe64( volume_id );
   uint64_t file_id_nb = htobe64( file_id );
   uint64_t xattr_nonce_nb = htobe64( (uint64_t)xattr_nonce );
   int* order = NULL;
   size_t num_xattrs = 0;
   size_t i = 0;
   
   if( !((xattr_names != NULL && xattr_values != NULL && xattr_lengths != NULL) || (xattr_names == NULL && xattr_values == NULL && xattr_lengths == NULL)) ) {
       return -EINVAL;
   }
   
    
   SHA256_CTX context;
   SHA256_Init( &context ); 
   
   if( xattr_names != NULL && xattr_values != NULL && xattr_lengths != NULL ) {
       
       // count xattrs
       for( num_xattrs = 0; xattr_names[num_xattrs] != NULL && xattr_values[num_xattrs] != NULL; num_xattrs++ );
        
       if( xattr_names[num_xattrs] != NULL || xattr_values[num_xattrs] != NULL ) {
           return -EINVAL;
       }
       
       order = SG_CALLOC( int, num_xattrs );
       if( order == NULL ) {
           return -ENOMEM;
       }
        
       for( i = 0; i < num_xattrs; i++ ) {
           order[i] = i;
       }
        
       // sort order on xattrs--xattr_names[order[i]] is the ith xattr
       nlopt_qsort_r( order, num_xattrs, sizeof(int), xattr_names, ms_client_xattr_compar );
   }
   
   // hash metadata
   SHA256_Update( &context, &volume_id_nb, sizeof(volume_id_nb) );
   SHA256_Update( &context, &file_id_nb, sizeof(file_id_nb) );
   SHA256_Update( &context, &xattr_nonce_nb, sizeof(xattr_nonce_nb) );
   
   if( xattr_names != NULL && xattr_values != NULL && xattr_lengths != NULL ) {
        
       // hash xattrs 
       for( size_t i = 0; i < num_xattrs; i++ ) {
        
           SHA256_Update( &context, xattr_names[ order[i] ], strlen(xattr_names[order[i]]) );
           SHA256_Update( &context, xattr_values[ order[i] ], xattr_lengths[ order[i] ] );
       }
       
       SG_safe_free( order );
   }
   
   SHA256_Final( sha256_buf, &context );

   //////////////////////////////////////////////////////////////
   char printable_hashbuf[ SHA256_DIGEST_LENGTH*2 + 1 ];
   sha256_printable_buf( sha256_buf, printable_hashbuf );
   SG_debug("xattr hash for %" PRIX64 ".%" PRId64 " is %s\n", file_id, xattr_nonce, printable_hashbuf );
   //////////////////////////////////////////////////////////////

   return 0;
}


// extract xattr names, values, and lengths from an ms reply 
// return 0 on success, and set *xattr_names, *xattr_values, *xattr_lengths (the former two will be NULL-terminated)
// return -ENOMEM on OOM 
// return -EINVAL for mismatched quantities of each.
static int ms_client_extract_xattrs( ms::ms_reply* reply, char*** xattr_names, char*** xattr_values, size_t** xattr_lengths ) {
   
   int rc = 0;
   
   if( reply->xattr_names_size() != reply->xattr_values_size() ) {
      return -EINVAL;
   }
   
   size_t num_xattrs = reply->xattr_names_size();
   char** ret_names = NULL;
   char** ret_values = NULL;
   size_t* ret_lengths = NULL;
   
   ret_names = SG_CALLOC( char*, num_xattrs + 1 );
   ret_values = SG_CALLOC( char*, num_xattrs + 1 );
   ret_lengths = SG_CALLOC( size_t, num_xattrs + 1 );
   
   if( ret_names == NULL || ret_values == NULL || ret_lengths == NULL ) {
      SG_safe_free( ret_names );
      SG_safe_free( ret_values );
      SG_safe_free( ret_lengths );
      return -ENOMEM;
   }
   
   for( size_t i = 0; i < num_xattrs; i++ ) {
      
      char* name = SG_strdup_or_null( reply->xattr_names(i).c_str() );
      if( name == NULL ) {
         rc = -ENOMEM;
         break;
      }
      
      char* value = SG_CALLOC( char, reply->xattr_values(i).size() );
      if( value == NULL ) {
         
         SG_safe_free( name );
         rc = -ENOMEM;
         break;
      }
      
      memcpy( value, reply->xattr_values(i).data(), reply->xattr_values(i).size() );
      
      ret_names[i] = name;
      ret_values[i] = value;
      ret_lengths[i] = reply->xattr_values(i).size();
   }
   
   if( rc == -ENOMEM ) {
      
      SG_FREE_LIST( ret_names, free );
      SG_FREE_LIST( ret_values, free );
      
      SG_safe_free( ret_lengths );
      return rc;
   }
   
   *xattr_names = ret_names;
   *xattr_values = ret_values;
   *xattr_lengths = ret_lengths;
   return 0;
}


// fetch and verify all xattrs.
// this method should only be called by the coordinator for the file.
// return 0 on success
// return -EPERM if we failed to verify the set of xattrs against the hash
// return -ENOENT if the file doesn't exist or either isn't readable or writable.
// return -ENODATA if the semantics in flags can't be met.
// return -ENOMEM if OOM 
// return -ENODATA if the replied message has no xattr field
// return -EBADMSG on reply's signature mismatch
// return -EPROTO on HTTP 400-level error
// return -EREMOTEIO for HTTP 500-level error 
// return -errno on socket, connect, and recv related errors
int ms_client_fetchxattrs( struct ms_client* client, uint64_t volume_id, uint64_t file_id, int64_t xattr_nonce, unsigned char* xattr_hash, char*** xattr_names, char*** xattr_values, size_t** xattr_lengths ) {
   
   char* fetchxattrs_url = NULL;
   ms::ms_reply reply;
   int rc = 0;
   char** names = NULL;
   char** values = NULL;
   size_t* lengths = NULL;
   unsigned char hash_buf[SHA256_DIGEST_LENGTH];
   
   fetchxattrs_url = ms_client_fetchxattrs_url( client->url, volume_id, ms_client_volume_version( client ), ms_client_cert_version( client ), file_id );
   if( fetchxattrs_url == NULL ) {
      return -ENOMEM;
   }
   
   rc = ms_client_read( client, fetchxattrs_url, &reply );
   
   SG_safe_free( fetchxattrs_url );
   
   if( rc != 0 ) {
      SG_error("ms_client_read(fetchxattrs) rc = %d\n", rc );
      return rc;
   }
   else {
      
      // check for errors 
      if( reply.error() != 0 ) {
         SG_error("MS replied with error %d\n", reply.error() );
         return reply.error();
      }
      
      // extract the xattrs
      rc = ms_client_extract_xattrs( &reply, &names, &values, &lengths );
      if( rc != 0 ) {
         SG_error("ms_client_extract_xattrs rc = %d\n", rc );
         return rc;
      }
      
      // find the hash over them 
      rc = ms_client_xattr_hash( hash_buf, volume_id, file_id, xattr_nonce, names, values, lengths );
      if( rc != 0 ) {
         
         SG_FREE_LIST( names, free );
         SG_FREE_LIST( values, free );
         SG_safe_free( lengths );
         return rc;
      }
      
      // hash match?
      if( sha256_cmp( xattr_hash, hash_buf ) != 0 ) {
         
         SG_FREE_LIST( names, free );
         SG_FREE_LIST( values, free );
         SG_safe_free( lengths );
         
         char xattr_hash_printable[2*SHA256_DIGEST_LENGTH + 1];
         char hash_buf_printable[2*SHA256_DIGEST_LENGTH + 1];
         
         if( xattr_hash != NULL ) {
            sha256_printable_buf( xattr_hash, xattr_hash_printable );
         }
         else {
            memset( xattr_hash_printable, '0', 2*SHA256_DIGEST_LENGTH );
            xattr_hash_printable[ 2*SHA256_DIGEST_LENGTH ] = 0;
         }
         
         sha256_printable_buf( hash_buf, hash_buf_printable );
         
         SG_error("hash mismatch: %" PRIX64 ".%" PRId64 ": %s != %s\n", file_id, xattr_nonce, xattr_hash_printable, hash_buf_printable );
         
         return -EPERM;
      }
      
      // hash match!
      // can save 
      *xattr_names = names;
      *xattr_values = values;
      *xattr_lengths = lengths;
     
      SG_debug("Got xattrs for %" PRIX64 "\n", file_id );
      for( int i = 0; names[i] != NULL; i++ ) {

         char value_buf[25];
         memset( value_buf, 0, 25 );
         memcpy( value_buf, values[i], MIN(20, lengths[i]) );
         memcpy( value_buf + MIN(20, lengths[i]), "...\0", 4);

         SG_debug("   xattr: '%s' = '%s' (length %zu)\n", names[i], value_buf, lengths[i] );
      }

      return 0;
   }
}


// make a putxattr request 
// NOTE: shallow-copies
// return 0 on success 
int ms_client_putxattr_request( struct ms_client* ms, struct md_entry* ent, char const* xattr_name, char const* xattr_value, size_t xattr_value_len, unsigned char* xattr_hash, struct ms_client_request* request ) {
   
   memset( request, 0, sizeof(struct ms_client_request) );
   
   request->op = ms::ms_request::PUTXATTR;
   request->flags = 0;
   
   request->ent = ent;
   
   request->xattr_name = xattr_name;
   request->xattr_value = xattr_value;
   request->xattr_value_len = xattr_value_len;
   request->xattr_hash = xattr_hash;
   
   return 0;
}

// put a new xattr name/value, new xattr nonce, and xattr signature.
// only the coordinator should call this, and only to keep its xattrs replica coherent with the MS
// return 0 on success
// return -EPERM if we failed to sign the xattr, for some reason
// return -ENOENT if the file doesn't exist or either isn't readable or writable.
// return -ENODATA if the semantics in flags can't be met.
// return -ENOMEM if OOM 
// return -ENODATA if the replied message has no xattr field
// return -EBADMSG on reply's signature mismatch
// return -EPROTO on HTTP 400-level error, or an MS RPC-level error
// return -EREMOTEIO for HTTP 500-level error 
// return -errno on socket, connect, and recv related errors
// WARN: ent->ent_sig and ent->ent_sig_len will be changed.  If ent->ent_sig is not NULL, it will be free'd (be sure that it's heap-allocated!)
int ms_client_putxattr( struct ms_client* client, struct md_entry* ent, char const* xattr_name, char const* xattr_value, size_t xattr_value_len, unsigned char* xattr_hash ) {
   
   int rc = 0;
   
   struct ms_client_request request;
   struct ms_client_request_result result;

   unsigned char* old_xattr_hash = NULL;
   unsigned char* old_sig = NULL;
   size_t old_sig_len = 0;
   
   memset( &request, 0, sizeof(struct ms_client_request) );
   memset( &result, 0, sizeof(struct ms_client_request_result) );
   
   ms_client_putxattr_request( client, ent, xattr_name, xattr_value, xattr_value_len, xattr_hash, &request );

   // sign the resulting entry
   old_sig = ent->ent_sig;
   old_sig_len = ent->ent_sig_len;
   old_xattr_hash = ent->xattr_hash;

   ent->ent_sig = NULL;
   ent->ent_sig_len = 0;
   ent->xattr_hash = xattr_hash;

   rc = md_entry_sign( client->gateway_key, ent, &ent->ent_sig, &ent->ent_sig_len );
   if( rc != 0 ) {
      SG_error("md_entry_sign rc = %d\n", rc );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPERM;
   }
   
   rc = ms_client_single_rpc( client, &request, &result );
   if( rc != 0 ) {
      SG_error("ms_client_single_rpc rc = %d\n", rc );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return rc;
   }
   
   if( result.reply_error != 0 ) {
      // protocol-level error 
      SG_error("MS reply error %d\n", result.reply_error );
      ms_client_request_result_free( &result );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPROTO;
   }
   
   if( result.rc != 0 ) {
      SG_error("MS operation rc = %d\n", result.rc );
      ms_client_request_result_free( &result );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPERM;
   }
   
   ms_client_request_result_free( &result );
   if( old_sig != NULL ) {
      SG_safe_free( old_sig );
   }

   return 0;
}


// make a removexattr request 
// return 0 on success 
int ms_client_removexattr_request( struct ms_client* client, struct md_entry* ent, char const* xattr_name, unsigned char* xattr_hash, struct ms_client_request* request ) {
   
   memset( request, 0, sizeof(struct ms_client_request) );
   
   request->op = ms::ms_request::REMOVEXATTR;
   request->flags = 0;
   
   request->ent = ent;
   
   request->xattr_name = xattr_name;
   request->xattr_hash = xattr_hash;
   
   return 0;
}

// remove an xattr.
// fails if the file isn't readable or writable, or the xattr exists and it's not writable
// succeeds even if the xattr doesn't exist (i.e. idempotent)
// return 0 on success 
// return -ENOMEM if OOM 
// return -ENODATA if the replied message has no xattr field
// return -EBADMSG on reply's signature mismatch
// return -EPROTO on HTTP 400-level error or an MS RPC error
// return -EREMOTEIO for HTTP 500-level error 
// return -errno on socket, connect, and recv related errors
int ms_client_removexattr( struct ms_client* client, struct md_entry* ent, char const* xattr_name, unsigned char* xattr_hash ) {
   
   int rc = 0;
   struct ms_client_request request;
   struct ms_client_request_result result;

   unsigned char* old_xattr_hash = NULL;
   unsigned char* old_sig = NULL;
   size_t old_sig_len = 0;
   
   memset( &request, 0, sizeof(struct ms_client_request) );
   memset( &result, 0, sizeof(struct ms_client_request_result) );
  
   SG_debug("remove xattr '%s' from %" PRIX64 "\n", xattr_name, ent->file_id );

   ms_client_removexattr_request( client, ent, xattr_name, xattr_hash, &request );
   
   // sign the resulting entry
   old_sig = ent->ent_sig;
   old_sig_len = ent->ent_sig_len;
   old_xattr_hash = ent->xattr_hash;

   ent->ent_sig = NULL;
   ent->ent_sig_len = 0;
   ent->xattr_hash = xattr_hash;

   rc = md_entry_sign( client->gateway_key, ent, &ent->ent_sig, &ent->ent_sig_len );
   if( rc != 0 ) {
      SG_error("md_entry_sign rc = %d\n", rc );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPERM;
   }
   
   rc = ms_client_single_rpc( client, &request, &result );
   if( rc != 0 ) {
      SG_error("ms_client_single_rpc rc = %d\n", rc );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return rc;
   }
   
   if( result.reply_error != 0 ) {
      // protocol-level error 
      SG_error("MS reply error %d\n", result.reply_error );
      ms_client_request_result_free( &result );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPROTO;
   }
   
   if( result.rc != 0 ) {
      SG_error("MS operation rc = %d\n", result.rc );
      ms_client_request_result_free( &result );

      SG_safe_free( ent->ent_sig );
      ent->ent_sig = old_sig;
      ent->ent_sig_len = old_sig_len;
      ent->xattr_hash = old_xattr_hash;
      return -EPERM;
   }
   
   ms_client_request_result_free( &result );
   if( old_sig != NULL ) {
      SG_safe_free( old_sig );
   }

   return 0;
}

