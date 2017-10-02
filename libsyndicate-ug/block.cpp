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
 * @file libsyndicate-ug/block.cpp
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief User Gateway block related functions
 *
 * @see libsyndicate-ug/block.h
 */

#include "block.h"
#include "inode.h"


/**
 * @brief Initialize a dirty block by copying in a buffer
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int UG_dirty_block_init_ram( struct UG_dirty_block* dirty_block, struct SG_manifest_block* info, char const* buf, size_t buflen ) {
   
   int rc = 0;
   char* buf_dup = NULL;
   
   memset( dirty_block, 0, sizeof(struct UG_dirty_block) );
   
   rc = SG_manifest_block_dup( &dirty_block->info, info );
   if( rc != 0 ) {
      
      return rc;
   }
   
   buf_dup = SG_CALLOC( char, buflen );
   if( buf_dup == NULL ) {
      
      SG_manifest_block_free( &dirty_block->info );
      return -ENOMEM;
   }
   
   SG_chunk_init( &dirty_block->buf, buf_dup, buflen );
   
   dirty_block->unshared = true;
   
   clock_gettime( CLOCK_MONOTONIC, &dirty_block->load_time );
   
   return 0;
}


/**
 * @brief Init a dirty block by taking onwership of a buffer
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */ 
int UG_dirty_block_init_ram_nocopy( struct UG_dirty_block* dirty_block, struct SG_manifest_block* info, char* buf, size_t buflen ) {
   
   int rc = 0;
   
   memset( dirty_block, 0, sizeof(struct UG_dirty_block) );
   
   rc = SG_manifest_block_dup( &dirty_block->info, info );
   if( rc != 0 ) {
      
      return rc;
   }
   
   SG_chunk_init( &dirty_block->buf, buf, buflen );
   
   dirty_block->unshared = false;
   
   clock_gettime( CLOCK_MONOTONIC, &dirty_block->load_time );
   
   return 0;
}


/**
 * @brief Set a dirty block's buffer.  Use with care.
 *
 * Only works if the block is *not* shared/RAM-allocated.  If unshared, frees the buffer first.
 * @return 0
 */
int UG_dirty_block_set_buf( struct UG_dirty_block* dest, struct SG_chunk* new_buf ) {

   if( !UG_dirty_block_unshared( dest ) && UG_dirty_block_in_RAM( dest ) ) {
      SG_error("%s", "BUG: dirty block not in RAM\n");
      exit(1);
   }

   if( UG_dirty_block_unshared( dest ) ) {
      SG_chunk_free( &dest->buf );
   }

   dest->buf = *new_buf;
   return 0;
}

/**
 * @brief Set version
 *
 * Calls SG_manifest_block_set_version
 * @see SG_manifest_block_set_version
 */
int UG_dirty_block_set_version( struct UG_dirty_block* blk, int64_t version ) {
   SG_manifest_block_set_version( &blk->info, version );
   return 0;
}

/**
 * @brief Load a block from the cache
 *
 * Load into dirty_block->buf
 * If dirty_block->buf is allocated, this loads the deserialized block directly into it.
 * If it is not allocated, it will be with malloc.
 * Transform it using the driver
 * Do NOT mark it dirty.
 * dirty_block must be instantiated, but must not be in RAM
 * @retval 0 Success
 * @retval -ENOENT Not cached 
 * @retval -EIO Failed to access the cache
 * @retval -ENOMEM Out of Memory
 * @retval -EINVAL dirty_block is in RAM
 * @retval -ENODATA Failed to serialize the block
 */
int UG_dirty_block_load_from_cache( struct SG_gateway* gateway, char const* fs_path, uint64_t file_id, uint64_t file_version, struct UG_dirty_block* dirty_block, struct SG_IO_hints* io_hints ) {
   
   int rc = 0;
   struct SG_request_data reqdat;
   
   struct SG_chunk raw_block;
   struct SG_chunk block_buf;
   struct SG_chunk* buf_ptr = NULL;

   memset( &raw_block, 0, sizeof(struct SG_chunk) );
   memset( &block_buf, 0, sizeof(struct SG_chunk) );

   if( UG_dirty_block_is_flushed( dirty_block ) ) { 

      SG_error("BUG: block [%" PRIu64 ".%" PRId64 "] flushed or mmap'ed\n", UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ) );
      exit(1);
   }

   if( UG_dirty_block_in_RAM( dirty_block ) ) {

      // load directly 
      buf_ptr = UG_dirty_block_buf( dirty_block );
   }
   else {

      // implementation must allocate 
      buf_ptr = &block_buf;
   }

   rc = SG_request_data_init_block( gateway, fs_path, file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), &reqdat );
   if( rc != 0 ) {
      return rc;
   }

   SG_request_data_set_IO_hints( &reqdat, io_hints );

   // fetch serialized block from cache 
   rc = SG_gateway_cached_block_get_raw( gateway, &reqdat, &raw_block );
   
   if( rc != 0 ) {

      if( rc != -ENOENT ) {
          SG_error("SG_gateway_cached_block_get_raw( %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] ) rc = %d\n", 
                       file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), rc );
      }

      SG_request_data_free( &reqdat );

      if( rc == -ENOENT) {
         return -ENOENT;
      }
      else {
         return -EIO;
      }
   }

   // deserialize (might allocate buf_ptr)
   rc = SG_gateway_impl_deserialize( gateway, &reqdat, &raw_block, buf_ptr );

   SG_request_data_free( &reqdat );
   SG_chunk_free( &raw_block );

   if( rc == -ENOSYS ) {
      // no-op 
      rc = 0;
   }

   if( rc != 0 ) {
       
      SG_error("SG_gateway_impl_deserialize( %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] ) rc = %d\n", 
                   file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), rc );

      if( rc != -ENOMEM ) {
          rc = -ENODATA;
      }

      return rc;
   }

   // put into place, if not there already
   if( buf_ptr == &block_buf ) {
      UG_dirty_block_set_buf( dirty_block, buf_ptr );
   }

   return 0;
}

/**
 * @brief Free dirty block 
 * @return 0
 */
int UG_dirty_block_free( struct UG_dirty_block* dirty_block ) {
   
   SG_manifest_block_free( &dirty_block->info );
   
   if( dirty_block->unshared ) {
      
      SG_chunk_free( &dirty_block->buf );
   }
   
   return 0;
}


/**
 * @brief Free dirty block, but not the block data
 *
 * This is useful for recovering from errors, when we don't want to free the buffer passed into the dirty block
 * @see SG_manifest_block_free
 * @return 0
 */
int UG_dirty_block_free_keepbuf( struct UG_dirty_block* dirty_block ) {
   
   SG_manifest_block_free( &dirty_block->info );
   return 0;
}


/**
 * @brief Free a block map
 * @see UG_dirty_block_free
 * @return 0
 */
int UG_dirty_block_map_free( UG_dirty_block_map_t* dirty_blocks ) {
   
   for( UG_dirty_block_map_t::iterator itr = dirty_blocks->begin(); itr != dirty_blocks->end(); itr++ ) {
      
      UG_dirty_block_free( &itr->second );
   }
   
   dirty_blocks->clear();
   return 0;
}


/**
 * @brief Free a block map, but don't touch the buffers
 * @see UG_dirty_block_free_keepbuf 
 * @return 0
 */
int UG_dirty_block_map_free_keepbuf( UG_dirty_block_map_t* dirty_blocks ) {
   
   for( UG_dirty_block_map_t::iterator itr = dirty_blocks->begin(); itr != dirty_blocks->end(); itr++ ) {
      
      UG_dirty_block_free_keepbuf( &itr->second );
   }
   
   dirty_blocks->clear();
   return 0;
}


/**
 * @brief Set the dirty flag on a dirty block 
 * @return 0
 */
int UG_dirty_block_set_dirty( struct UG_dirty_block* dirty_block, bool dirty ) {
   
   dirty_block->dirty = dirty;
   return 0;
}


/**
 * @brief Set the unshared flag on a dirty block
 *
 * This is the case if we gift data into a block
 * @return 0
 */
int UG_dirty_block_set_unshared( struct UG_dirty_block* dirty_block, bool unshared ) {

   dirty_block->unshared = true;
   return 0;
}


/**
 * @brief Flush a dirty block from RAM to disk.
 *
 * Put the cache-write future into *dirty_block, and re-calculate the hash over the block's driver-serialized form
 * @param[out] *dirty_block The cache-write future
 * @note Be careful not to free dirty_block until the future has been finalized!
 * @note Not thread-safe--don't try flushing the same block twice
 * @retval 0 Success
 * @retval -EINPROGRESS This block is already being flushed
 * @retval -EINVAL The block was already flushed, or is not in RAM, or is not dirty
 * @retval -ENODATA Failed to serialize the block 
 * @retval -errno Cache failure
 */
int UG_dirty_block_flush_async( struct SG_gateway* gateway, char const* fs_path, uint64_t file_id, int64_t file_version, struct UG_dirty_block* dirty_block, struct SG_IO_hints* io_hints ) {
   
   int rc = 0;
   struct md_cache_block_future* fut = NULL;
   struct SG_request_data reqdat;
   struct SG_chunk serialized_data;
   struct ms_client* ms = SG_gateway_ms( gateway );

   SG_debug("Flush %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] (%s)\n", file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), fs_path );

   if( dirty_block->block_fut != NULL ) {
      
      // in progress
      return -EINPROGRESS;
   }
  
   if( !UG_dirty_block_in_RAM( dirty_block ) ) {
      // can't flush
      SG_error("BUG: block %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] is not in RAM\n", file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ) );
      exit(1);
   }

   if( UG_dirty_block_is_flushed( dirty_block ) ) {
      
      // already on disk
      SG_error("BUG: block %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] is flushed to disk already\n", file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ) );
      exit(1);
   }

   if( !UG_dirty_block_dirty( dirty_block ) ) {
      
      // not dirty
      return 0;
   }    
  
   /* 
   if( !dirty_block->dirty ) {
      
      // nothing to do 
      SG_error("BUG: block %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] is not dirty\n", file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ) );
      exit(1);
   }
   */
  
   // synthesize a block request
   rc = SG_request_data_init_block( gateway, fs_path, file_id, file_version, UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), &reqdat );
   if( rc != 0 ) {

      SG_error("SG_request_data_init rc = %d\n", rc );
      return rc;
   }
    
   SG_request_data_set_IO_hints( &reqdat, io_hints );
   
   // serialize and update hash 
   rc = UG_dirty_block_serialize( gateway, &reqdat, dirty_block, &serialized_data );
   if( rc != 0 ) {

      SG_error("UG_dirty_block_serialize([%" PRIu64 ".%" PRId64 "]) rc = %d\n", UG_dirty_block_id( dirty_block ), UG_dirty_block_version( dirty_block ), rc );
      SG_request_data_free( &reqdat );
      return -ENODATA;
   }
    
   // gift the serialized data to the cache, but tell the cache not to evict it (we'll do that ourselves)
   rc = SG_gateway_cached_block_put_raw_async( gateway, &reqdat, &serialized_data, SG_CACHE_FLAG_UNSHARED | SG_CACHE_FLAG_MANAGED, &fut );
   SG_request_data_free( &reqdat );
   
   if( rc != 0 ) {
      
      SG_error("SG_gateway_cached_block_put_raw_async( %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] rc = %d\n", 
               file_id, file_version, dirty_block->info.block_id, dirty_block->info.block_version, rc );

      SG_chunk_free( &serialized_data );
   }
   
   else {
     
      dirty_block->file_id = file_id;
      dirty_block->file_version = file_version;
      dirty_block->volume_id = ms_client_get_volume_id( ms );
      dirty_block->block_fut = fut;
      dirty_block->managed = true;
   }
   
   return rc;
}


/**
 * @brief Wait for a block to get flushed.
 *
 * If the block is not dirty and is not flushing, return 0.
 * If free_chunk is set, free dirty_block's RAM buffer as well if we successfully flush
 * @retval 0 Success
 * @retval -EINVAL The block is dirty, but the block is not being flushed.
 * @retval -errno Flush failure (in which case, none of the above side-effects occur)
 */
int UG_dirty_block_flush_finish_ex( struct UG_dirty_block* dirty_block, bool free_chunk ) {
   
   int rc = 0;
   
   struct md_cache_block_future* block_fut = dirty_block->block_fut;
   
   if( block_fut == NULL && dirty_block->dirty ) {
      
      // nothing to do
      return -EINVAL;
   }

   else if( dirty_block->flushed ) {
      // nothing to do 
      return 0;
   }
   
   else if( !dirty_block->dirty && block_fut == NULL ) {
     
      // clean up 
      goto UG_dirty_block_flush_finish_ex_out;
   }
   
   rc = md_cache_flush_write( block_fut );
   if( rc != 0 ) {
      
      SG_error("md_cache_flush_write( %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] ) rc = %d\n", 
               md_cache_block_future_file_id( block_fut ), md_cache_block_future_file_version( block_fut ), md_cache_block_future_block_id( block_fut ), md_cache_block_future_block_version( block_fut ), rc );
      
      return rc;
   }
   
   /*
   // detach the file descriptor from the future, and put it into the dirty block (in order to keep the data referenced) 
   block_fd = md_cache_block_future_release_fd( block_fut );
   if( block_fd < 0 ) {
      
      SG_error("md_cache_block_future_release_fd( %" PRIX64 ".%" PRId64 "[%" PRIu64 ".%" PRId64 "] ) rc = %d\n", 
               md_cache_block_future_file_id( block_fut ), md_cache_block_future_file_version( block_fut ), md_cache_block_future_block_id( block_fut ), md_cache_block_future_block_version( block_fut ), block_fd );
      
      return block_fd;
   }
   close( block_fd );
   */

UG_dirty_block_flush_finish_ex_out:
   if( free_chunk && dirty_block->unshared ) {
      SG_chunk_free( &dirty_block->buf );
   }
   
   if( block_fut != NULL ) {
      md_cache_block_future_free( block_fut );
   }
   
   dirty_block->block_fut = NULL;
   dirty_block->flushed = true;
   
   return 0;
}


/**
 * @brief Wait for a block to get flushed.
 *
 * Put the block future's fd into the dirty_block, and free the dirty block's memory
 * @retval 0 Success
 * @retval -errno Flush failure
   @see UG_dirty_block_flush_finish_ex
 */
int UG_dirty_block_flush_finish( struct UG_dirty_block* dirty_block ) {
   
   return UG_dirty_block_flush_finish_ex( dirty_block, true );
}


/**
 * @brief Wait for a block to get flushed.
 *
 * Don't free the associated chunk, if present.
 * Put the block future's fd into the dirty_block, and free the dirty block's memory
 * @retval 0 Success
 * @retval -errno Flush failure
 * @see UG_dirty_block_flush_finish_ex
 */ 
int UG_dirty_block_flush_finish_keepbuf( struct UG_dirty_block* dirty_block ) {
   
   return UG_dirty_block_flush_finish_ex( dirty_block, false );
}


/**
 * @brief Unshare a block's buffer, make a private copy, and replace the buffer 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL There is no associated RAM buffer for this dirty block, or if this block was already unshare
 */
int UG_dirty_block_buf_unshare( struct UG_dirty_block* dirty_block ) {
   
   int rc = 0;
   struct SG_chunk chunk_dup;
   
   if( dirty_block->buf.data == NULL ) {
      
      return -EINVAL;
   }
   
   if( dirty_block->unshared ) {
      
      return -EINVAL;
   }
   
   rc = SG_chunk_dup( &chunk_dup, &dirty_block->buf );
   if( rc != 0 ) {
      
      return rc;
   }
   
   dirty_block->buf = chunk_dup;
   dirty_block->unshared = true;
   
   clock_gettime( CLOCK_MONOTONIC, &dirty_block->load_time );
   
   return 0;
}


/**
 * @brief Find the IDs of the first aligned block and last aligned block given an offset and a write length 
 *
 * The IDs of the first and last block that correspond to whole blocks in the range [offset, offset + buf_len].
 * @return 0
 */
int UG_dirty_block_aligned( off_t offset, size_t buf_len, uint64_t block_size, uint64_t* aligned_start_id, uint64_t* aligned_end_id, off_t* aligned_start_offset, off_t* last_block_len ) {
   
   int rc = 0;
   
   uint64_t first_affected_block = offset / block_size;
   uint64_t first_aligned_block = 0;
   off_t first_aligned_block_offset = 0;  // offset into buf where the first aligned block starts
   
   uint64_t last_aligned_block = 0;
   uint64_t last_block_overflow = 0;
   
   // is the first block aligned?
   if( offset > 0 && (offset % block_size) != 0 ) {
      
      // nope--it's the next one 
      first_aligned_block = first_affected_block + 1;
      
      first_aligned_block_offset = block_size - (offset % block_size);
   }
   else {
      
      // yup--aligned 
      first_aligned_block = first_affected_block;
      
      first_aligned_block_offset = 0;
   }
  
   last_aligned_block = (offset + buf_len) / block_size;
   if( last_aligned_block > 0 ) {
      last_aligned_block--;
   }

   if( (offset + buf_len) > 0 && (offset + buf_len) % block_size != 0 ) {
      last_block_overflow = (offset + buf_len) % block_size;
   }

   if( aligned_start_id != NULL ) {
      
      *aligned_start_id = first_aligned_block;
   }
   
   if( aligned_end_id != NULL ) {
      
      *aligned_end_id = last_aligned_block;
   }
   
   if( aligned_start_offset != NULL ) {
      
      *aligned_start_offset = first_aligned_block_offset;
   }

   if( last_block_len != NULL ) {

      *last_block_len = last_block_overflow;
   }
   
   return rc;
}


/**
 * @brief Evict a block 
 * @return 0
 * @see md_cache_evict_block
 */
int UG_dirty_block_evict( struct md_syndicate_cache* cache, struct UG_inode* inode, struct UG_dirty_block* block ) {

   uint64_t flags = 0;
   if( block->managed ) {
      flags |= SG_CACHE_FLAG_MANAGED;
   }

   // evict, if needed
   md_cache_evict_block( cache, UG_inode_file_id( inode ), UG_inode_file_version( inode ), UG_dirty_block_id( block ), UG_dirty_block_version( block ), flags );
   return 0;
} 


/**
 * @brief Evict and free a dirty block 
 * @return 0
 * @relatesalso UG_dirty_block_evict
 * @relatesalso UG_dirty_block_free
 */
int UG_dirty_block_evict_and_free( struct md_syndicate_cache* cache, struct UG_inode* inode, struct UG_dirty_block* block ) {
  
   UG_dirty_block_evict( cache, inode, block );
   UG_dirty_block_free( block );
   return 0;
}


// getters
/// Get dirty block ID (block_id)
uint64_t UG_dirty_block_id( struct UG_dirty_block* blk ) {
   return blk->info.block_id;
}

/// Get dirty block version (block_version)
int64_t UG_dirty_block_version( struct UG_dirty_block* blk ) {
   return blk->info.block_version;
}

/**
 * @brief Get dirty block hash buffer
 * @param[out] hash_buf The hash buffer
 * @note can only be called once the block has been (re)hashed
 * @return 0
 */
int UG_dirty_block_hash_buf( struct UG_dirty_block* blk, unsigned char* hash_buf ) {

   if( SG_manifest_block_hash( &blk->info ) == NULL ) {
      SG_error("BUG: hash for block [%" PRIu64 ".%" PRId64 "] is NULL\n", UG_dirty_block_id( blk ), UG_dirty_block_version( blk ) );
      exit(1);
   }

   memcpy( hash_buf, SG_manifest_block_hash( &blk->info ), SG_BLOCK_HASH_LEN );
   return 0;
}

/// Get durty block buffer (blk->buf)
struct SG_chunk* UG_dirty_block_buf( struct UG_dirty_block* blk ) {
   return &blk->buf;
}

/**
 * @brief Open the block, based on whether or not it is caller- or cache-managed.
 * @return The file handle on success
 * @retval -errno Failure
 */
int UG_dirty_block_open( struct SG_gateway* gateway, uint64_t file_id, int64_t file_version, uint64_t block_id, int64_t block_version, int open_flags, uint64_t cache_flags ) {

   return md_cache_open_block( SG_gateway_cache( gateway ), file_id, file_version, block_id, block_version, open_flags, cache_flags );
}

/// Get dirty block info (blk->info)
struct SG_manifest_block* UG_dirty_block_info( struct UG_dirty_block* blk ) {
   return &blk->info;
}

/// Get dirty block unshared (blk->unshared)
bool UG_dirty_block_unshared( struct UG_dirty_block* blk ) {
   return blk->unshared;
}

/// Get block dirty (blk->dirty)
bool UG_dirty_block_dirty( struct UG_dirty_block* blk ) {
   return blk->dirty;
}

/**
 * @brief Get flushing state of block (blk->block_fut)
 * @retval True Flushing
 * @retval False Not flushing
 */
bool UG_dirty_block_is_flushing( struct UG_dirty_block* blk ) {
   return (blk->block_fut) != NULL;
}

/**
 * @brief Get if block is flushed (blk->flushed)
 * @retval True Flushed
 * @retval False Not flushed
 */
bool UG_dirty_block_is_flushed( struct UG_dirty_block* blk ) {
   return blk->flushed;
}

/**
 * @brief Get if block is in RAM
 * @retval True In RAM
 * @retval False Not in RAM
 */
bool UG_dirty_block_in_RAM( struct UG_dirty_block* blk ) {
   return (blk->buf.data != NULL);
}

/// Get block logical offset (logical_write_offset)
uint64_t UG_dirty_block_get_logical_offset( struct UG_dirty_block* blk ) {
   return blk->logical_write_offset;
}

/// Get block logical length (logical_write_length)
uint64_t UG_dirty_block_get_logical_len( struct UG_dirty_block* blk ) {
   return blk->logical_write_length;
}

/// Set the block logical write given an offset and length
void UG_dirty_block_set_logical_write( struct UG_dirty_block* blk, uint64_t logical_offset, uint64_t logical_len ) {
   blk->logical_write_offset = logical_offset;
   blk->logical_write_length = logical_len;
}

/**
 * @brief Re-calculate the hash of the block
 *
 * The block must be resident in memory, but not mmap'ed
 * Store it into its block info
 * @note NOT ATOMIC
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int UG_dirty_block_rehash( struct UG_dirty_block* blk, char const* serialized_data, size_t serialized_data_len ) {

   unsigned char* hash = NULL;
   unsigned char hash_buf[SHA256_DIGEST_LENGTH];
   memset( hash_buf, 0, SHA256_DIGEST_LENGTH );

   char hash_str[2*SHA256_DIGEST_LENGTH + 1];
   memset( hash_str, 0, 2*SHA256_DIGEST_LENGTH+1 );

   sha256_hash_buf( serialized_data, serialized_data_len, hash_buf );
   sha256_printable_buf( hash_buf, hash_str );
   SG_debug("Hash of block [%" PRIu64 ".%" PRId64 "] (%p) is now %s\n", UG_dirty_block_id( blk ), UG_dirty_block_version( blk ), blk, hash_str );

   // give to block info
   hash = sha256_dup( hash_buf );
   if( hash == NULL ) {
     return -ENOMEM;
   } 
   SG_manifest_block_set_hash( &blk->info, hash );
   return 0;
}


/**
 * @brief Serialize a block, and update its hash 
 *
 * @note The block must be resident in memory
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int UG_dirty_block_serialize( struct SG_gateway* gateway, struct SG_request_data* reqdat, struct UG_dirty_block* block, struct SG_chunk* serialized_data ) {

   int rc = 0;
   struct SG_IO_hints io_hints;
   off_t old_chunk_size = 0;
   struct SG_chunk* block_buf = NULL;

   // sanity check: must be in RAM 
   if( !UG_dirty_block_in_RAM( block ) ) {
     SG_error("BUG: block [%" PRIu64 ".%" PRId64 "] is not in RAM\n", UG_dirty_block_id( block ), UG_dirty_block_version( block ) );
     exit(1);
   } 

   memset( serialized_data, 0, sizeof(struct SG_chunk) );

   // it's possible that the block given actually has a different logical length 
   // (i.e. the given block could be at the end of the file, and contain zero-padding).
   SG_request_data_get_IO_hints( reqdat, &io_hints );
   block_buf = UG_dirty_block_buf( block );

   old_chunk_size = block_buf->len;
   if( io_hints.block_size > 0 ) {
       block_buf->len = io_hints.block_size;
   }
   
   // serialize the block
   rc = SG_gateway_impl_serialize( gateway, reqdat, block_buf, serialized_data );
   
   // revert 
   if( io_hints.block_size > 0 ) {
      block_buf->len = old_chunk_size;
   }

   if( rc != 0 && rc != -ENOSYS ) {

      SG_error("UG_impl_block_serialize([%" PRIu64 ".%" PRId64 "]) rc = %d\n", UG_dirty_block_id( block ), UG_dirty_block_version( block ), rc );
      return rc;
   }
   else {
      rc = 0;
   }
   
   // calculate the new block hash 
   rc = UG_dirty_block_rehash( block, serialized_data->data, serialized_data->len );

   if( rc != 0 ) {

      SG_error("UG_dirty_block_rehash([%" PRIu64 ".%" PRId64 "]) rc = %d\n", UG_dirty_block_id( block ), UG_dirty_block_version( block ), rc );
      SG_chunk_free( serialized_data );
      return rc;
   }

   return 0;
}
