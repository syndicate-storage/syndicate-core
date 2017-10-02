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

/**
 * @file libsyndicate-ug/replication.cpp
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief User Gateway replication related functions
 *
 * @see libsyndicate-ug/replication.h
 */

#include "replication.h"
#include "inode.h"
#include "core.h"
#include "sync.h"
#include "client.h"

#define REPLICA_NOT_STARTED     0
#define REPLICA_IN_PROGRESS     1
#define REPLICA_SUCCESS         2

/// Snapshot of inode fields needed for replication and garbage collection 
struct UG_replica_context {
  
   struct UG_state* state;                      ///< Pointer to UG

   char* fs_path;                               ///< Path to the file to replicate
   SG_messages::Request* controlplane_request;  ///< Control-plane component
   struct SG_chunk serialized_manifest;         ///< Serialized manifest, if we're replicating the manifest
   struct SG_client_request_async* datareq;     ///< Data-plane stream generator 

   struct md_entry inode_data;                  ///< Exported inode
   uint64_t* affected_blocks;                   ///< Block IDs affected by the write
   size_t num_affected_blocks;                  ///< Length of the above list
   
   struct SG_manifest write_delta;              ///< Write delta to send to the coordinator

   struct UG_RG_context* rg_context;            ///< RPC contexts to all RGs
   
   bool flushed_blocks;                         ///< If true, then the blocks have all been flushed to disk and can be replicated 
   bool sent_vacuum_log;                        ///< If true, then we've told the MS about the manifest and blocks we're about to replicate 
   bool replicated_blocks;                      ///< If true, then we've replicated blocks and manifests
   bool sent_ms_update;                         ///< If true, then we've sent the new inode metadata to the MS

   // for use while sending blocks... 
   size_t cur_block;                            ///< current block (use while sending blocks)
   int cur_block_fd;                            ///< current block file descriptor (use while sending blocks)
   bool sent_manifest;                          ///< If true, the manifest was sent
   off_t manifest_offset;                       ///< The manifest offset
   size_t total_data_upload_len;                ///< Total size of the data upload
};


/**
 * @brief Data-plane stream function for libcurl 
 * @note cls is a UG_replica_context
 * @see UG_replica_content
 * @return Number of bytes written on success
 * @retvals CURL_READFUNC_ABORT Failure
 */
size_t UG_replica_dataplane_stream( char* buf, size_t count, size_t nmemb, void* cls ) {

   struct SG_client_request_async* datareq = (struct SG_client_request_async*)cls;
   struct UG_replica_context* rctx = (struct UG_replica_context*)SG_client_request_async_cls( datareq );
   struct SG_gateway* gateway = UG_state_gateway( rctx->state );
   uint64_t block_id = 0;
   int64_t block_version = 0;
   int rc = 0;
   size_t total_read = 0;
   size_t total_copy = 0;

   while( true ) {

      // do we need to send the manifest?
      if( rctx->serialized_manifest.data != NULL && !rctx->sent_manifest ) {

         // send manifest first 
         total_copy = MIN( count * nmemb, (unsigned)rctx->serialized_manifest.len - (unsigned)rctx->manifest_offset );
         SG_debug("Send manifest: %zu bytes (total: %zu, offset: %jd)\n", total_copy, count * nmemb, rctx->manifest_offset);

         memcpy( buf, rctx->serialized_manifest.data + rctx->manifest_offset, total_copy );

         rctx->manifest_offset += total_copy;

         // done?
         if( rctx->manifest_offset >= rctx->serialized_manifest.len ) {
            rctx->sent_manifest = true;
            SG_debug("Sent manifest (%zu bytes)\n", rctx->serialized_manifest.len);
         }

         total_read += total_copy;
         if( total_read >= count * nmemb ) {
            // filled buf
            break;
         }
      }

      // send the next block
      if( rctx->cur_block_fd < 0 ) {

         // are there more blocks? 
         if( rctx->cur_block >= rctx->num_affected_blocks ) {
            // out of data
            SG_debug("Out of blocks at block #%" PRIu64 "\n", rctx->cur_block );
            return total_read;
         }

         // next block...
         block_id = rctx->affected_blocks[ rctx->cur_block ];
         rc = SG_manifest_get_block_version( &rctx->write_delta, block_id, &block_version );
         if( rc < 0 ) {
            // should never happen
            SG_error("BUG: FATAL: missing block version for %" PRIu64 "\n", block_id );
            exit(1);
         }

         // open the next block 
         rctx->cur_block_fd = UG_dirty_block_open( gateway, rctx->inode_data.file_id, rctx->inode_data.version, block_id, block_version, O_RDONLY, SG_CACHE_FLAG_MANAGED );
         if( rctx->cur_block_fd < 0 ) {
            SG_error("Failed to open %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "]: rc = %d\n", rctx->inode_data.file_id, rctx->inode_data.version, block_id, block_version, rctx->cur_block_fd );
            return CURL_READFUNC_ABORT;
         }

         rctx->cur_block++;
         SG_debug("Send block %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] (%zu out of %zu)\n", rctx->inode_data.file_id, rctx->inode_data.version, block_id, block_version, rctx->cur_block-1, rctx->num_affected_blocks );
      }

      // stream in, while we still can 
      rc = md_read_uninterrupted( rctx->cur_block_fd, buf + total_read, count * nmemb - total_read );
      if( rc < 0 ) {
         SG_error("md_read_uninterrupted(%" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "]) rc = %d\n", rctx->inode_data.file_id, rctx->inode_data.version, block_id, block_version, rctx->cur_block_fd );
         
         // shutdown 
         close( rctx->cur_block_fd );
         rctx->cur_block_fd = -1;
         return CURL_READFUNC_ABORT;
      }

      SG_debug("Send block: %d bytes (total: %zu, offset: %zu)\n", rc, count * nmemb, total_read);
      total_read += rc;

      if( rc == 0 || (unsigned)rc < count * nmemb - total_read ) {
         // EOF; begin next
         SG_debug("EOF at %zu bytes\n", total_read); 
         close( rctx->cur_block_fd );
         rctx->cur_block_fd = -1;
         continue;
      }

      if( total_read >= count * nmemb ) {
         // filled buf 
         break;
      }
   }

   return total_read;
}

/// Create a new dataplane stream 
struct SG_client_request_async* UG_replica_dataplane_stream_new( struct UG_replica_context* rctx ) {

   struct SG_client_request_async* datareq = SG_client_request_async_new();
   if( datareq == NULL ) {
      return NULL;
   }

   SG_client_request_async_init( datareq, UG_replica_dataplane_stream, rctx->total_data_upload_len, rctx );
   return datareq;
}

/// Create a new replica context
struct UG_replica_context* UG_replica_context_new() {
   return SG_CALLOC( struct UG_replica_context, 1 );
}

/**
 * @brief Sign and serialize a manifest to a chunk
 * @param[out] *raw_chunk The populated chunk
 * @retval Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EPERM The signing or serialization failed 
 * @retval -ENODATA Failed to serialize with the driver
 */
static int UG_replica_sign_serialize_manifest_to_chunk( struct SG_gateway* gateway, char const* fs_path, struct SG_manifest* manifest, struct SG_chunk* raw_chunk ) {

   int rc = 0;
   SG_messages::Manifest mmsg;
   struct ms_client* ms = SG_gateway_ms( gateway );
   EVP_PKEY* privkey = ms_client_my_privkey( ms );
   struct SG_chunk chunk;
   char* chunk_buf = NULL;
   size_t chunk_buflen = 0;

   struct SG_request_data reqdat;
   
   rc = SG_request_data_init_manifest( gateway, fs_path, SG_manifest_get_file_id( manifest ), SG_manifest_get_file_version( manifest ), SG_manifest_get_modtime_sec( manifest ), SG_manifest_get_modtime_nsec( manifest ), &reqdat );
   if( rc != 0 ) {
      return rc;
   }
   
   // serialize 
   rc = SG_manifest_serialize_to_protobuf( manifest, &mmsg );
   if( rc != 0 ) {
      
      SG_request_data_free( &reqdat );

      if( rc == -ENOMEM ) {
         return rc;
      }
      else {
         return -EPERM;
      }
   }

   // sign 
   rc = md_sign< SG_messages::Manifest >( privkey, &mmsg );
   if( rc != 0 ) {

      SG_request_data_free( &reqdat );
      return rc;
   }

   // convert to chunk 
   rc = md_serialize< SG_messages::Manifest >( &mmsg, &chunk_buf, &chunk_buflen );
   if( rc != 0 ) {

      SG_request_data_free( &reqdat );
      return rc;
   }

   SG_chunk_init( &chunk, chunk_buf, chunk_buflen );

   // serialize the chunk
   rc = SG_gateway_impl_serialize( gateway, &reqdat, &chunk, raw_chunk );
   SG_request_data_free( &reqdat );
   SG_chunk_free( &chunk );

   if( rc == -ENOSYS ) {
      // no-op
      rc = 0;
   }

   if( rc != 0 ) {

      SG_error("SG_gateway_impl_serialize rc = %d\n", rc );
      return -ENODATA;
   }

   return rc;
}


/**
 * @brief Generate chunk info from a manifest chunk
 * @param[out] *chunk_info Populated chunk information
 * @retval Success
 * @retval -ENOMEM Out of Memory 
 */
static int UG_replica_make_manifest_chunk_info( struct SG_chunk* manifest_chunk, int64_t mtime_sec, int32_t mtime_nsec, struct SG_manifest_block* chunk_info ) {

   int rc = 0;
   unsigned char* hash = NULL;

   hash = sha256_hash_data( manifest_chunk->data, manifest_chunk->len );
   if( hash == NULL ) {
      return -ENOMEM;
   }

   rc = SG_manifest_block_init( chunk_info, mtime_sec, mtime_nsec, hash, SG_BLOCK_HASH_LEN );
   SG_safe_free( hash );

   if( rc != 0 ) {

      return rc;
   }

   SG_manifest_block_set_type( chunk_info, SG_MANIFEST_BLOCK_TYPE_MANIFEST );

   return rc;
}


/**
 * @brief Generate chunk info from a dirty block.
 *
 * The block needs to have been flushed to disk.
 * @param[out] *chunk_info Populated chunk information
 * @attention Not thread-safe w.r.t. the block; the block must *not* be modified while this method is being called!
 * @retval Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EPERM The block could not be mapped into RAM
 */
static int UG_replica_make_block_chunk_info( struct UG_dirty_block* block, uint64_t block_id, int64_t block_version, struct SG_manifest_block* chunk_info ) {

   unsigned char hash[SG_BLOCK_HASH_LEN];
   int rc = 0;

   rc = UG_dirty_block_hash_buf( block, hash );
   if( rc != 0 ) {

      // should never happen 
      if( rc == -ERANGE ) {

         SG_error("BUG: block has a non-standard hash (not SG_BLOCOK_HASH_LEN (%d)) bytes\n", SG_BLOCK_HASH_LEN );
         exit(1);
      }
      else {
         return rc;
      }
   }
   
   rc = SG_manifest_block_init( chunk_info, block_id, block_version, hash, SG_BLOCK_HASH_LEN );
   if( rc != 0 ) {
      return rc;
   }

   SG_manifest_block_set_type( chunk_info, SG_MANIFEST_BLOCK_TYPE_BLOCK );
   SG_manifest_block_set_logical_write( chunk_info, UG_dirty_block_get_logical_offset( block ), UG_dirty_block_get_logical_len( block ) );
   return rc;
}


/**
 * @brief Given the whole manifest and the blocks to replicate, calculate the delta to send to the coordinator.
 * @param[out] *write_delta The populated write_delta
 * @retval Success
 * @retval -ENOMEM Out of Memory
 */
static int UG_replica_make_write_delta( struct SG_manifest* whole_manifest, UG_dirty_block_map_t* flushed_blocks, struct SG_manifest* write_delta ) {

   int rc = 0;
   rc = SG_manifest_init( write_delta, SG_manifest_get_volume_id( whole_manifest ), SG_manifest_get_coordinator( whole_manifest ), SG_manifest_get_file_id( whole_manifest ), SG_manifest_get_file_version( whole_manifest ) );
   if( rc != 0 ) {
      return rc;
   }

   if( flushed_blocks != NULL ) {
      for( UG_dirty_block_map_t::iterator itr = flushed_blocks->begin(); itr != flushed_blocks->end(); itr++ ) {

         struct SG_manifest_block* write_block_info = UG_dirty_block_info( &itr->second );
         rc = SG_manifest_put_block( write_delta, write_block_info, true );
         if( rc != 0 ) {

            // EINVAL indicats a bug
            if( rc != -ENOMEM ) {
               SG_error("BUG: SG_manifest_put_block rc = %d\n", rc );
               exit(1);
            }

            SG_manifest_free( write_delta );
            return rc;
         }
      }
   }

   SG_manifest_set_size( write_delta, SG_manifest_get_file_size(whole_manifest) );

   return 0;
}


/**
 * @brief Create the replica control-plane message.
 *
 * This can be a PUTCHUNKS command, in which case, the message will contain blocks and (if we're the coordinator) the manifest
 * All blocks in flushed_blocks need to be dirty in this case
 * This can also be a RENAME_HINT command, in which case,the new_path argument and manifest will be used.
 * @param[out] *request Populate the request (does not calculate size and offset fields in the request)
 * @param[out] *serialize_manifest Populate serialized_manifest
 * @return 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL Invalid arguments
 */
static int UG_replica_context_make_controlplane_message( struct UG_state* ug, uint64_t request_type, char const* fs_path, struct UG_inode* inode, struct SG_manifest* manifest,
                                                         UG_dirty_block_map_t* flushed_blocks, char const* new_path, SG_messages::Request* request, struct SG_chunk* serialized_manifest ) {
   
   int rc = 0;
   int num_chunks = 0;
   struct SG_request_data reqdat;
   struct SG_gateway* gateway = UG_state_gateway( ug );
   size_t chunks_capacity = 0;
   struct SG_manifest_block* chunk_info = NULL;
   struct SG_chunk manifest_chunk;
   uint64_t coordinator_id = UG_inode_coordinator_id( inode );
   bool we_are_coordinator = (UG_inode_coordinator_id( inode ) == SG_gateway_id( gateway ));

   if( request_type != SG_messages::Request::PUTCHUNKS && request_type != SG_messages::Request::RENAME_HINT ) {
      return -EINVAL;
   }

   if( request_type == SG_messages::Request::RENAME_HINT && new_path == NULL ) {
      return -EINVAL;
   }

   memset( &manifest_chunk, 0, sizeof(struct SG_chunk) );

   // get basic info
   rc = SG_request_data_init_common( gateway, fs_path, UG_inode_file_id( inode ), UG_inode_file_version( inode ), &reqdat );
   if( rc != 0 ) {
      goto UG_replica_context_make_controlplane_message_fail;
   }

   // make chunk info 
   // we will only replicate the manifest if we're the coordinator
   if( we_are_coordinator ) {
       chunks_capacity = 1;   // include the manifest 
   }
   
   if( flushed_blocks != NULL ) {
       chunks_capacity += flushed_blocks->size();
   }

   chunk_info = SG_manifest_block_alloc( chunks_capacity );
   if( chunk_info == NULL ) {
      rc = -ENOMEM;
      goto UG_replica_context_make_controlplane_message_fail;
   }

   // manifest chunk, if we're the coordinator 
   if( we_are_coordinator ) {
       
       SG_debug("We coordinate %" PRIX64 ", so replicate manifest\n", UG_inode_file_id( inode ) );

       rc = UG_replica_sign_serialize_manifest_to_chunk( gateway, fs_path, manifest, &manifest_chunk );
       if( rc != 0 ) {

          SG_error("UG_replica_sign_serialize_manifest_to_chunk rc = %d\n", rc );
          goto UG_replica_context_make_controlplane_message_fail;
       }

       // manifest chunk info 
       rc = UG_replica_make_manifest_chunk_info( &manifest_chunk, SG_manifest_get_modtime_sec( manifest ), SG_manifest_get_modtime_nsec( manifest ), &chunk_info[0] );
       if( rc != 0 ) {

          SG_error("UG_replica_make_manifest_chunk_info(%s) rc = %d\n", fs_path, rc );
          goto UG_replica_context_make_controlplane_message_fail;
       }
   
       num_chunks++;
   }

   if( flushed_blocks != NULL ) {
      
      for( UG_dirty_block_map_t::iterator itr = flushed_blocks->begin(); itr != flushed_blocks->end(); itr++ ) {

         struct UG_dirty_block* block = &itr->second;
         rc = UG_replica_make_block_chunk_info( block, UG_dirty_block_id( block ), UG_dirty_block_version( block ), &chunk_info[num_chunks] );
         if( rc != 0 ) {

            SG_error("UG_replica_make_chunk_info rc = %d\n", rc );
            goto UG_replica_context_make_controlplane_message_fail;
         }

         num_chunks++;
      }
   }

   // generate the message, but don't sign it yet (still need to add data-plane metadata)
   if( request_type == SG_messages::Request::PUTCHUNKS ) {
       rc = SG_client_request_PUTCHUNKS_setup_ex( gateway, request, &reqdat, coordinator_id, chunk_info, num_chunks, false );
   }
   else {
       rc = SG_client_request_RENAME_HINT_setup( gateway, request, &reqdat, coordinator_id, &chunk_info[0], new_path );
   }
   
   if( rc != 0 ) {

      goto UG_replica_context_make_controlplane_message_fail;
   }

   if( we_are_coordinator ) {
       // transfer manifest 
       *serialized_manifest = manifest_chunk;
       memset( &manifest_chunk, 0, sizeof(struct SG_chunk) );
   }
   else {
       memset( serialized_manifest, 0, sizeof(struct SG_chunk) );
   }

UG_replica_context_make_controlplane_message_fail:

   // clean up
   SG_request_data_free( &reqdat );

   for( int i = 0; i < num_chunks; i++ ) {
      SG_manifest_block_free( &chunk_info[i] );
   }

   SG_safe_free( chunk_info );
   
   return rc;
}


/**
 * @brief Create the replica data-plane message, using an already-initialized control-plane request.
 *
 * Write out the serialized data-plane message to disk, and add chunk information (size, offset, type) to the control-plane request.
 * @note Each block in flushed_blocks must be dirty and already flushed to disk (i.e. it must have a file descriptor)
 * @param[out] *request Populate the size and offset fields for each block in the control-plane request
 * @retval 0 Success
 * @retval -errno fs-related errors.
 * @retval -ENAMETOOLONG Temporary path overflow
 */
static int UG_replica_context_make_dataplane_message( struct UG_state* ug, SG_messages::Request* request, struct SG_chunk* manifest_chunk, UG_dirty_block_map_t* flushed_blocks, size_t* total_data_len ) {

   int rc = 0;
   int fd = -1;
   int manifest_count = 0;
   uint64_t off = 0;
   struct SG_gateway* gateway = UG_state_gateway( ug );
   struct md_syndicate_conf* conf = SG_gateway_conf( gateway );
   char* data_root = md_conf_get_data_root( conf );
   char tmppath[PATH_MAX];
   struct stat sb;
   SG_messages::ManifestBlock* block_info = NULL;

   if( manifest_chunk != NULL && manifest_chunk->data != NULL ) {
      manifest_count = 1;
   }

   rc = snprintf( tmppath, PATH_MAX-1, "%s/.replica-XXXXXX", data_root );
   if( rc >= PATH_MAX-1 ) {
      return -ENAMETOOLONG;
   }

   // sanity check: all blocks must exist in flushed_blocks and be flushed to disk (i.e. we need a file descriptor)
   // however, the first block_info in the controlplane message refers to the *manifest* chunk, so we will not consider it here.
   if( flushed_blocks != NULL ) {
   
      // sanity check: request must be initialized 
      if( (unsigned)request->blocks_size() != (unsigned)flushed_blocks->size() + manifest_count ) {
         SG_error("%s", "BUG: control-plane request is not initialized\n");
         exit(1);
      }

      for( int i = 1; i < request->blocks_size(); i++ ) {

         block_info = request->mutable_blocks(i);
         struct UG_dirty_block* block = NULL;
         UG_dirty_block_map_t::iterator itr = flushed_blocks->find( block_info->block_id() );

         // must exist...
         if( itr == flushed_blocks->end() ) {
            SG_error("BUG: block %" PRIu64 " not present\n", block_info->block_id() );
            exit(1);
         }

         block = &itr->second;
         if( !UG_dirty_block_is_flushed( block ) ) {

            SG_error("BUG: block %" PRIu64 " not flushed\n", block_info->block_id() );
            exit(1);
         }
      }
   }
   else if( request->blocks_size() != 1 ) {
      SG_error("%s", "BUG: request to replicate non-existent blocks\n");
      exit(1);
   }

   // flush manifest, if we're the coordinator  
   if( manifest_count == 1 ) {

       // sanity check.... 
       if( request->coordinator_id() != SG_gateway_id( gateway )) {
          SG_error("BUG: manifest given, but we do not coordinate %" PRIX64 "\n", request->file_id() );
          exit(1);
       }

       // put manifest chunk data 
       block_info = request->mutable_blocks(0);
       block_info->set_offset( 0 );
       block_info->set_size( manifest_chunk->len );

       off += manifest_chunk->len;
   }

   // flush each block
   // NOTE: if we're the coordinator, blocks[0] should be the manifest info; blocks[1..n] are the block info
   // otherwise, blocks[0...n] are all blocks
   for( int i = manifest_count; i < request->blocks_size(); i++ ) {
    
      block_info = request->mutable_blocks(i);
      struct UG_dirty_block* block = &(*flushed_blocks)[ block_info->block_id() ];
      int block_fd = 0;

      block_fd = UG_dirty_block_open( gateway, request->file_id(), request->file_version(), UG_dirty_block_id( block ), UG_dirty_block_version( block ), O_RDONLY, SG_CACHE_FLAG_MANAGED );
      if( block_fd < 0 ) {
         SG_error("UG_dirty_block_open(%" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "]) rc = %d\n", request->file_id(), request->file_version(), UG_dirty_block_id( block ), UG_dirty_block_version( block ), block_fd );
         rc = block_fd;
         goto UG_replica_context_make_dataplane_message_fail;
      }

      // fetch data from the serialized block on disk
      rc = fstat( block_fd, &sb );
      if( rc != 0 ) {
         rc = -errno;
         close( block_fd );
         SG_error("fstat(%d) rc = %d\n", block_fd, rc );
         goto UG_replica_context_make_dataplane_message_fail;
      }

      close( block_fd );
      
      // extend with info
      block_info->set_offset( off );
      block_info->set_size( sb.st_size );

      off += sb.st_size;
   }

   // success!
   // *dataplane_fd = fd;
   *total_data_len = off;
   return 0;

UG_replica_context_make_dataplane_message_fail:

   // clean up
   if( fd >= 0 ) {
      close( fd );
      fd = -1;
   }

   return rc;
}


/**
 * @brief Set up a replica context from an inode's dirty blocks and its current *whole* manifest.
 *
 * @attention inode->entry should be read-locked
 * @note flushed_blocks is allowed to be NULL, in which case only the manifest will be replicated.
 * @note if non-NULL, then flushed_blocks must all be dirty and in RAM
 * @retval Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL Invalid input (i.e. a non-dirty inode)
 */
int UG_replica_context_init_ex( struct UG_replica_context* rctx, struct UG_state* ug, uint64_t request_type, char const* fs_path,
                               char const* new_path, struct UG_inode* inode, struct SG_manifest* manifest, UG_dirty_block_map_t* flushed_blocks ) {
   
   int rc = 0;
   SG_messages::Request* controlplane = NULL;
   struct SG_chunk serialized_manifest;
   uint64_t* affected_blocks = NULL;
   size_t num_affected_blocks = 0;
   size_t total_bytes = 0;
   struct SG_gateway* gateway = UG_state_gateway( ug );
   EVP_PKEY* gateway_privkey = SG_gateway_private_key( gateway );
   
   memset( rctx, 0, sizeof( struct UG_replica_context ) );
   
   if( flushed_blocks != NULL ) {

      if( inode == NULL ) {
         return -EINVAL;
      }

      affected_blocks = SG_CALLOC( uint64_t, flushed_blocks->size() );
      if( affected_blocks == NULL ) {
         return -ENOMEM;
      }
      
      // sanity check 
      for( UG_dirty_block_map_t::iterator itr = flushed_blocks->begin(); itr != flushed_blocks->end(); itr++ ) {
        
         struct UG_dirty_block* block = &itr->second;

         // not dirty?
         if( !UG_dirty_block_dirty( block ) ) {
         
            SG_error("BUG: %" PRIX64 "[%" PRIu64 ".%" PRId64 "] not dirty\n", UG_inode_file_id( inode ), itr->first, UG_dirty_block_version( block ) );
            exit(1);
         }

         // must be flushed to disk
         if( !UG_dirty_block_is_flushed( block ) ) {

            SG_error("BUG: %" PRIX64 "[%" PRIu64 ".%" PRId64 "] is not flushed\n", UG_inode_file_id( inode ), itr->first, UG_dirty_block_version( block ) );
            exit(1);
         }

         affected_blocks[num_affected_blocks] = itr->first;
         num_affected_blocks++;
      }
   }

   rctx->state = ug;
   rctx->affected_blocks = affected_blocks;
   rctx->num_affected_blocks = num_affected_blocks;

   rctx->rg_context = UG_RG_context_new();
   if( rctx->rg_context == NULL ) {

      return -ENOMEM;
   }

   rc = UG_RG_context_init( ug, rctx->rg_context );
   if( rc != 0 ) {

      SG_error("UG_RG_context_init rc = %d\n", rc );
      UG_RG_context_free( rctx->rg_context );
      SG_safe_free( rctx->rg_context );
      return (rc == -ENOMEM ? rc : -EPERM);
   }

   // create fields
   rctx->fs_path = SG_strdup_or_null( fs_path );
   if( rctx->fs_path == NULL ) {

      UG_replica_context_free( rctx );
      return rc;
   }

   rc = UG_inode_export( &rctx->inode_data, inode, 0 );
   if( rc != 0 ) {

      UG_replica_context_free( rctx );
      return rc;
   }

   rc = UG_replica_make_write_delta( manifest, flushed_blocks, &rctx->write_delta );
   if( rc != 0 ) {

      UG_replica_context_free( rctx );
      return rc; 
   }

   // make control-plane component
   controlplane = SG_safe_new( SG_messages::Request() );
   if( controlplane == NULL ) {

      UG_replica_context_free( rctx );
      return rc;
   }

   rc = UG_replica_context_make_controlplane_message( ug, request_type, fs_path, inode, manifest, flushed_blocks, new_path, controlplane, &serialized_manifest );
   if( rc != 0 ) {

      UG_replica_context_free( rctx );
      SG_safe_delete( controlplane );
      SG_error("UG_replica_context_make_controlplane_message rc = %d\n", rc );
      return rc;
   }

   // make data-plane component
   rc = UG_replica_context_make_dataplane_message( ug, controlplane, &serialized_manifest, flushed_blocks, &total_bytes );
   if( rc != 0 ) {

      UG_replica_context_free( rctx );
      SG_safe_delete( controlplane );
      SG_chunk_free( &serialized_manifest );
      SG_error("UG_replica_context_make_dataplane_message rc = %d\n", rc );
      return rc;
   }

   rctx->serialized_manifest = serialized_manifest;
   rctx->total_data_upload_len = total_bytes;
   rctx->datareq = UG_replica_dataplane_stream_new( rctx );

   if( rctx->datareq == NULL ) {
      // OOM 
      rc = -ENOMEM;
      UG_replica_context_free( rctx );
      SG_safe_delete( controlplane );
      return rc;
   }

   // sign control-plane.
   // since it has the hashes of the chunks, it attests to the data plane's integrity and authenticity as well
   rc = md_sign< SG_messages::Request >( gateway_privkey, controlplane );
   if( rc != 0 ) {

      UG_replica_context_free( rctx );
      SG_safe_delete( controlplane );
      SG_error("md_sign rc = %d\n", rc );
      return rc;
   }

   rctx->controlplane_request = controlplane;
   rctx->cur_block_fd = -1;
   rctx->cur_block = 0;
   rctx->sent_manifest = false;
   rctx->manifest_offset = 0;
   SG_debug("Will replicate %zu bytes total for '%s'\n", total_bytes, fs_path);
   return rc;
}


/// Short-hand for making a PUTCHUNKS request
int UG_replica_context_init( struct UG_replica_context* rctx, struct UG_state* ug, char const* fs_path,
                             struct UG_inode* inode, struct SG_manifest* manifest, UG_dirty_block_map_t* flushed_blocks ) {

   return UG_replica_context_init_ex( rctx, ug, SG_messages::Request::PUTCHUNKS, fs_path, NULL, inode, manifest, flushed_blocks );
}


/// Short-hand for making a RENAME_HINT request
int UG_replica_context_init_rename_hint( struct UG_replica_context* rctx, struct UG_state* ug, char const* old_path, char const* new_path,
                                         struct UG_inode* inode, struct SG_manifest* manifest ) {

   return UG_replica_context_init_ex( rctx, ug, SG_messages::Request::RENAME_HINT, old_path, new_path, inode, manifest, NULL );
}

   

/**
 * @brief Free up a replica context 
 * @return 0
 */
int UG_replica_context_free( struct UG_replica_context* rctx ) {
   
   SG_safe_free( rctx->fs_path ); 
   md_entry_free( &rctx->inode_data );
   SG_manifest_free( &rctx->write_delta );
   SG_safe_delete( rctx->controlplane_request );
   UG_RG_context_free( rctx->rg_context );
   SG_safe_free( rctx->rg_context );
   SG_safe_free( rctx->affected_blocks );
   SG_chunk_free( &rctx->serialized_manifest );
   SG_safe_free( rctx->datareq );
   memset( rctx, 0, sizeof(struct UG_replica_context) );
   
   return 0;
}

/**
 * @brief Append a file's vacuum log on the MS
 *
 * Does *NOT* set rctx->sent_vacuum_log
 * @retval Success
 * @retval -ENOMEM Out of Memory 
 * @retval -errno Connection errors
 */
static int UG_replicate_vacuum_log( struct SG_gateway* gateway, struct UG_replica_context* rctx ) {
   
   int rc = 0;
   struct ms_vacuum_entry ve;
   struct ms_client* ms = SG_gateway_ms( gateway );
   
   // set up the vacuum entry
   rc = ms_client_vacuum_entry_init( &ve, rctx->inode_data.volume, ms_client_get_gateway_id( ms ), rctx->inode_data.file_id, rctx->inode_data.version,
                                     rctx->inode_data.manifest_mtime_sec, rctx->inode_data.manifest_mtime_nsec, rctx->affected_blocks, rctx->num_affected_blocks );
   
   if( rc != 0 ) {
      
      SG_error("ms_client_vacuum_entry_init( %" PRIX64 ".%" PRId64 " (%zu blocks) ) rc = %d\n", rctx->inode_data.file_id, rctx->inode_data.version, rctx->num_affected_blocks, rc );
      return rc;
   }
    
   // send it off
   rc = ms_client_append_vacuum_log_entry( ms, &ve );
   if( rc != 0 ) {
      
      SG_error("ms_client_append_volume_log_entry( %" PRIX64 ".%" PRId64 " (%zu blocks) ) rc = %d\n", rctx->inode_data.file_id, rctx->inode_data.version, rctx->num_affected_blocks, rc );
   }
   
   ms_client_vacuum_entry_free( &ve );
   
   return rc;
}


/**
 * @brief Replicate the blocks and manifest to a given gateway.
 *
``` 
   (0) make sure all blocks are flushed to disk cache
   (1) if we're the coordinator, append to this file's vacuum log on the MS 
   (2) replicate the blocks and manifest to each replica gateway
   (3) if we're the coordinator, send the new inode information to the MS
```
 * Free up blocks and manifest information as they succeed, so the caller can try a different gateway on a subsequent call resulting from a partial replication failure.
 * @retval Success
 * @retval -EIO Method failed to flush data to disk
 * @retval -EAGAIN Method should be called again, with the same arguments
 * @retval -ENOMEM Out of Memory
 * @retval -ETIMEDOUT The tranfser could not complete in time 
 * @retval -EREMOTEIO The HTTP error is >= 500
 * @retval -EINVAL Improper arguments
 * @retval -ENODATA The HTTP error was a 400-level error
 * @retval Other -errno on socket- and recv-related errors
 */
int UG_replicate( struct SG_gateway* gateway, struct UG_replica_context* rctx ) {
   
   int rc = 0;
   struct ms_client* ms = SG_gateway_ms( gateway );
   uint64_t volume_id = ms_client_get_volume_id( ms );
      
   // (1) make sure the MS knows about this replication request
   if( !rctx->sent_vacuum_log ) {
      
      SG_debug("%" PRIX64 ": begin replicating vacuum log\n", rctx->inode_data.file_id );

      rc = UG_replicate_vacuum_log( gateway, rctx );
      if( rc != 0 ) {
         
         SG_error("UG_replicate_vacuum_log( %" PRIX64 ".%" PRId64 " (%s) ) rc = %d\n", rctx->inode_data.file_id, rctx->inode_data.version, rctx->fs_path, rc );
         if( rc == -EINVAL ) {

            // indicates a bug 
            SG_error("BUG: UG_replicate_vacuum_log rc = %d\n", rc );
            return -EINVAL;
         }
         else {
            return -EAGAIN;
         }
      }
      else {
         
         // success!
         rctx->sent_vacuum_log = true;
         SG_debug("%" PRIX64 ": replicated vacuum log!\n", rctx->inode_data.file_id );
      }
   }
   
   // (2) replicate the manifest and each block to each replica gateway
   if( !rctx->replicated_blocks ) {
      
      SG_debug("%" PRIX64 ": begin replicating manifest and blocks\n", rctx->inode_data.file_id );

      // send off to all RGs
      rc = UG_RG_send_all( gateway, rctx->rg_context, rctx->controlplane_request, rctx->datareq );
      if( rc != 0 ) {
         
         SG_error("UG_RG_send_all() rc = %d\n", rc );
         
         return rc;
      }
      else {
         
         rctx->replicated_blocks = true;
         SG_debug("%" PRIX64 ": replicated manifest and blocks!\n", rctx->inode_data.file_id );
      }
   }
   
   // (3) update the record on the MS: either send the update to the MS ourselves (if we're the coordinator),
   // or send it to the coordinator directly.
   if( !rctx->sent_ms_update ) {
      
      SG_debug("%" PRIX64 ": begin sending MS updates\n", rctx->inode_data.file_id );

      // send it to the MS if we're the coordinator, 
      // or send it to the coordinator itself.
      struct SG_client_WRITE_data* write_data = SG_client_WRITE_data_new();
      struct timespec mtime;
      
      if( write_data == NULL ) {
          return -ENOMEM;
      }
      
      mtime.tv_sec = rctx->inode_data.mtime_sec;
      mtime.tv_nsec = rctx->inode_data.mtime_nsec;
      
      SG_client_WRITE_data_init( write_data );
      SG_client_WRITE_data_set_mtime( write_data, &mtime );
      SG_client_WRITE_data_set_write_delta( write_data, &rctx->write_delta );
      SG_client_WRITE_data_set_routing_info( write_data, volume_id, rctx->inode_data.coordinator, rctx->inode_data.file_id, rctx->inode_data.version );
     
      // NOTE: this could turn us into the coordinator 
      rc = UG_update( rctx->state, rctx->fs_path, write_data );
      if( rc != 0 ) {
          
         SG_error("UG_update('%s') rc = %d\n", rctx->fs_path, rc );
      }
      else {

         rctx->sent_ms_update = true;
         SG_debug("%" PRIX64 ": sent MS updates!\n", rctx->inode_data.file_id );
      }
      
      SG_safe_free( write_data );
   }

   // done!
   return rc;
}


/**
 * @brief Explicitly declare that we've made progress on replication.
 *
 * This call is meant to allow other components to implement different aspects of replication 
 * (i.e. syncing to disk, talking to the MS, etc.), so the replication subsystem doesn't try to do so.
 */
int UG_replica_context_hint( struct UG_replica_context* rctx, uint64_t flags ) {

   if( flags & UG_REPLICA_HINT_NO_MS_UPDATE ) {
      // don't send update to the MS
      rctx->sent_ms_update = true;
   }
   if( flags & UG_REPLICA_HINT_NO_MS_VACUUM ) {
      // don't update the vacuum log 
      rctx->sent_vacuum_log = true;
   }
   if( flags & UG_REPLICA_HINT_NO_RG_BLOCKS ) {
      // don't send blocks to the RGs 
      rctx->replicated_blocks = true;
   }

   return 0;
}
