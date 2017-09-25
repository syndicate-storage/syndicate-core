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
 * @file libsyndicate/ms/file.h
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief Header file for file.cpp
 *
 * @see libsyndicate/ms/file.cpp
 */

#ifndef _LIBSYNDICATE_MS_FILE_H_
#define _LIBSYNDICATE_MS_FILE_H_

#include "libsyndicate/ms/core.h"

/**
 * @brief Request to manipulate metadata on the MS
 * @note All data here is shallow-copied by request-generating methods, you don't have to free this structure.
 */
struct ms_client_request {
   int op;                          ///< Operation
   int flags;                       ///< Flags
   struct md_entry* ent;            ///< An entry
   
   uint64_t* affected_blocks;       ///< Optional: if performing an ms::ms_request::UPDATE due to a write
   size_t num_affected_blocks;      ///< Optional: if performing an ms::ms_request::UPDATE due to a write
   
   unsigned char* vacuum_signature; ///< Optional: if coordinator signature over the above
   size_t vacuum_signature_len;     ///< Optional: if coordinator signature over the above
   
   // optional: new xattr info 
   char const* xattr_name;          ///< Extended attribute name, optional: only if updated       
   char const* xattr_value;         ///< Extended attribute value, optional: only if updated     
   size_t xattr_value_len;          ///< Extended attribute value length, optional: only if updated        
   unsigned char* xattr_hash;       ///< Extended attribute hash, optional: only if updated
   
   struct md_entry* dest;           ///< Dest entry, optional: only if performing an ms::ms_request::RENAME 
   
   void* cls;                       ///< Caller-given context to associate with this request
};

/// Result of a single RPC operation 
struct ms_client_request_result {
   
   int rc;                      ///< Return code from the MS for the operation 
   int reply_error;             ///< Return code from the MS for the request
   uint64_t file_id;            ///< Inode on which we're operating
   struct md_entry* ent;        ///< Will be NULL if there is no entry for this operation 
};


/// Multi-entry response (e.g. getattr_multi, listdir, etc.) 
struct ms_client_multi_result {
   
   int reply_error;             ///< Result of the multi-RPC 
   int num_processed;           ///< Number of items processed by the MS
   
   struct md_entry* ents;       ///< Entries returned by the MS
   size_t num_ents;             ///< Number of entries returned by the MS
};


typedef list<struct ms_client_request*> ms_client_request_list;
 
/// Does an operation return an entry from the MS?
#define MS_CLIENT_OP_RETURNS_ENTRY( op ) ((op) == ms::ms_request::CREATE || (op) == ms::ms_request::UPDATE || (op) == ms::ms_request::CHCOORD)

extern "C" {
   
// high-level file metadata API
uint64_t ms_client_make_file_id();
int ms_client_create( struct ms_client* client, struct md_entry* ent_out, struct md_entry* ent );
int ms_client_mkdir( struct ms_client* client, struct md_entry* ent_out, struct md_entry* ent );
int ms_client_delete( struct ms_client* client, struct md_entry* ent );
int ms_client_update( struct ms_client* client, struct md_entry* ent_out, struct md_entry* ent );
int ms_client_coordinate( struct ms_client* client, struct md_entry* ent_out, struct md_entry* ent, unsigned char* xattr_hash );
int ms_client_rename( struct ms_client* client, struct md_entry* src, struct md_entry* dest );

// generate requests to be run
void ms_client_create_initial_fields( struct md_entry* ent );
int ms_client_create_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_create_async_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_mkdir_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_mkdir_async_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_update_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_update_async_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_update_write_request( struct ms_client* client, struct md_entry* ent, uint64_t* affected_blocks, size_t num_affected_blocks, unsigned char* vacuum_sig, size_t vacuum_sig_len, struct ms_client_request* request );
int ms_client_coordinate_request( struct ms_client* client, struct md_entry* ent, unsigned char* xattr_hash, struct ms_client_request* request );
int ms_client_rename_request( struct ms_client* client, struct md_entry* src, struct md_entry* dest, struct ms_client_request* request );
int ms_client_delete_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_delete_async_request( struct ms_client* client, struct md_entry* ent, struct ms_client_request* request );
int ms_client_request_set_cls( struct ms_client_request* request, void* cls );

// results 
int ms_client_download_parse_errors( struct md_download_context* dlctx );

// memory management
int ms_client_request_result_free( struct ms_client_request_result* result );
int ms_client_request_result_free_all( struct ms_client_request_result* results, size_t num_results );
int ms_client_multi_result_init( struct ms_client_multi_result* result, size_t num_ents );
int ms_client_multi_result_free( struct ms_client_multi_result* result );

// low-level RPC
int ms_client_single_rpc( struct ms_client* client, struct ms_client_request* request, struct ms_client_request_result* result );

// parsing
int ms_client_parse_reply( struct ms_client* client, ms::ms_reply* src, char const* buf, size_t buf_len );
int ms_client_num_expected_reply_ents( size_t num_reqs, int op );

}

#endif
