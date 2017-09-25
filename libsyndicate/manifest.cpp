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
 * @file libsyndicate/manifest.cpp
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief Manifest related functionality
 *
 * @see libsyndicate/manifest.h
 */

#include "libsyndicate/manifest.h"
#include "libsyndicate/gateway.h"

/// Read-lock a manifest 
static int SG_manifest_rlock( struct SG_manifest* manifest ) {
   return pthread_rwlock_rdlock( &manifest->lock );
}

/// Write-lock a manifest 
static int SG_manifest_wlock( struct SG_manifest* manifest ) {
   return pthread_rwlock_wrlock( &manifest->lock );
}

/// Unlock a manifest 
static int SG_manifest_unlock( struct SG_manifest* manifest ) {
   return pthread_rwlock_unlock( &manifest->lock );
}

/// Allocate manifest blocks 
struct SG_manifest_block* SG_manifest_block_alloc( size_t num_blocks ) {
   return SG_CALLOC( struct SG_manifest_block, num_blocks );
}

/**
 * @brief Initialize a manifest block (for a block of data, instead of a serialized manifest)
 * @note Duplicate all information 
 * @note Hash can be NULL
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_block_init( struct SG_manifest_block* dest, uint64_t block_id, int64_t block_version, unsigned char const* hash, size_t hash_len ) {
   
   memset( dest, 0, sizeof(struct SG_manifest_block) );
   
   if( hash_len > 0 ) {
      
      dest->hash = SG_CALLOC( unsigned char, hash_len );
      if( dest->hash == NULL ) {
         return -ENOMEM;
      }
      
      memcpy( dest->hash, hash, hash_len * sizeof(unsigned char) );
   }
  
   dest->type = SG_MANIFEST_BLOCK_TYPE_BLOCK;   // default type 
   dest->block_id = block_id;
   dest->block_version = block_version;
   dest->hash_len = hash_len;
   
   return 0;
}

/**
 * @brief Duplicate a manifest block 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_block_dup( struct SG_manifest_block* dest, struct SG_manifest_block* src ) {
   
   int rc = SG_manifest_block_init( dest, src->block_id, src->block_version, src->hash, src->hash_len );
   if( rc == 0 ) {
      
      // preserve dirty status and type
      dest->dirty = src->dirty;
      dest->type = src->type;
   }
   
   return rc;
}


/**
 * @brief Load a manifest block from a block protobuf 
 * @retval 0 Success 
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL on missing/invalid fields (i.e. the hash wasn't the right size)
 */
int SG_manifest_block_load_from_protobuf( struct SG_manifest_block* dest, const SG_messages::ManifestBlock* mblock ) {
   
   unsigned char const* hash = NULL;
   size_t hash_len = 0;
   
   if( mblock->has_hash() ) {
      
      // expect SG_BLOCK_HASH_LEN 
      if( mblock->hash().size() != SG_BLOCK_HASH_LEN ) {
         
         return -EINVAL;
      }
      
      hash = (unsigned char*)mblock->hash().data();
      hash_len = mblock->hash().size();
   }
   
   int rc = SG_manifest_block_init( dest, mblock->block_id(), mblock->block_version(), hash, hash_len );
   if( rc != 0 ) {
      return rc;
   }
   
   if( mblock->has_chunk_type() ) {
      dest->type = mblock->chunk_type();
   }

   return rc;
}

/**
 * @brief Set the dirty status for a block
 * @return 0
 */
int SG_manifest_block_set_dirty( struct SG_manifest_block* dest, bool dirty ) {
   
   dest->dirty = dirty;
   return 0;
}


/**
 * @brief Set the type of block
 * @return 0
 */
int SG_manifest_block_set_type( struct SG_manifest_block* dest, int type ) {
   dest->type = type;
   return 0;
}


/**
 * @brief Construct a manifest block from a chunk of data and versioning info 
 * @retval 0 Success 
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_block_init_from_chunk( struct SG_manifest_block* dest, uint64_t block_id, int64_t block_version, struct SG_chunk* chunk ) {
   
   int rc = 0;
   unsigned char* hash = NULL;
   size_t hash_len = 0;
   
   hash = sha256_hash_data( chunk->data, chunk->len );
   if( hash == NULL ) {
      
      return -ENOMEM;
   }
   
   hash_len = SG_BLOCK_HASH_LEN;
   
   rc = SG_manifest_block_init( dest, block_id, block_version, hash, hash_len );
   
   SG_safe_free( hash );
   
   return rc;
}


/**
 * @brief Allocate a manifest
 * @return A pointer to the memory block allocated by calloc
 */
struct SG_manifest* SG_manifest_new() {
   return SG_CALLOC( struct SG_manifest, 1 );
}

/**
 * @brief Initialize a fresh, empty manifest.
 * @note The modification time will be 0.
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_init( struct SG_manifest* manifest, uint64_t volume_id, uint64_t coordinator_id, uint64_t file_id, int64_t file_version ) {
   
   memset( manifest, 0, sizeof(struct SG_manifest) );
   
   manifest->blocks = SG_safe_new( SG_manifest_block_map_t() );
   if( manifest->blocks == NULL ) {
      
      return -ENOMEM;
   }
   
   int rc = pthread_rwlock_init( &manifest->lock, NULL );
   if( rc != 0 ) {
      
      SG_safe_free( manifest->blocks );
      return rc;
   }
   
   manifest->volume_id = volume_id;
   manifest->coordinator_id = coordinator_id;
   manifest->file_id = file_id;
   manifest->file_version = file_version;
   
   manifest->mtime_sec = 0;
   manifest->mtime_nsec = 0;
   manifest->stale = false;
   
   return 0;
}

/**
 * @brief Duplicate a manifest, including its freshness status and modtime
 * @param[out] dest New manifest
 * @param[in] src Manifest to duplicate
 * @note src must be unlocked or readlocked
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL src is malformed
 */
int SG_manifest_dup( struct SG_manifest* dest, struct SG_manifest* src ) {
   
   int rc = 0;
   rc = SG_manifest_init( dest, src->volume_id, src->coordinator_id, src->file_id, src->file_version );
   if( rc != 0 ) {
      return rc;
   }
   
   SG_manifest_rlock( src );
   
   for( SG_manifest_block_map_t::iterator itr = src->blocks->begin(); itr != src->blocks->end(); itr++ ) {
      
      struct SG_manifest_block new_block;
      
      rc = SG_manifest_block_dup( &new_block, &itr->second );
      if( rc != 0 ) {
         
         SG_manifest_unlock( src );
         
         // invalid or OOM 
         SG_manifest_free( dest );
         
         return rc;
      }
      
      try {
         (*dest->blocks)[ new_block.block_id ] = new_block;
      }
      catch( bad_alloc& ba ) {
         
         SG_manifest_unlock( src );
         SG_manifest_free( dest );
         
         return -ENOMEM;
      }
   }
   
   SG_manifest_unlock( src );
   
   // duplicate the remaining fields
   dest->mtime_sec = src->mtime_sec;
   dest->mtime_nsec = src->mtime_nsec;
   dest->stale = src->stale;
   
   return 0;
}


/**
 * @brief Clear a manifest's blocks
 * @retval 0 Success
 */ 
int SG_manifest_clear( struct SG_manifest* manifest ) {
   
   for( SG_manifest_block_map_t::iterator itr = manifest->blocks->begin(); itr != manifest->blocks->end(); itr++ ) {
    
      SG_manifest_block_free( &itr->second );
   }
   
   manifest->blocks->clear();
   return 0;
}

/**
 * @brief Clear a manifest's blocks, but don't free them
 * @retval 0 Success
 */
int SG_manifest_clear_nofree( struct SG_manifest* manifest ) {
   
   manifest->blocks->clear();
   return 0;
}


/**
 * @brief Load a manifest from a protocol buffer 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 * @retval -EINVAL Invalid block was encountered
 */
int SG_manifest_load_from_protobuf( struct SG_manifest* dest, const SG_messages::Manifest* mmsg ) {
   
   int rc = 0;
   
   pthread_rwlock_t lock;
   char* sig = NULL;
   size_t siglen = 0;

   rc = pthread_rwlock_init( &lock, NULL );
   if( rc != 0 ) {
      return rc;
   }

   sig = SG_CALLOC( char, mmsg->signature().size()+1 );
   if( sig == NULL ) {
      pthread_rwlock_destroy(&lock);
      return -ENOMEM;
   }
   
   // load each block 
   SG_manifest_block_map_t* blocks = SG_safe_new( SG_manifest_block_map_t() );
   if( blocks == NULL ) {
      
      SG_safe_free( sig );
      pthread_rwlock_destroy( &lock );
      return -ENOMEM;
   }
   
   for( int i = 0; i < mmsg->blocks_size(); i++ ) {
      
      const SG_messages::ManifestBlock& mblock = mmsg->blocks(i);
      struct SG_manifest_block block;
      
      rc = SG_manifest_block_load_from_protobuf( &block, &mblock );
      if( rc != 0 ) {
         
         // abort 
         SG_manifest_block_map_free( blocks );
         SG_safe_delete( blocks );
         
         SG_safe_free( sig );
         pthread_rwlock_destroy( &lock );
         return rc;
      }
      
      try {
         (*blocks)[ block.block_id ] = block;
      }
      catch( bad_alloc& ba ) {
         
         SG_manifest_block_map_free( blocks );
         SG_safe_delete( blocks );
         
         SG_safe_free( sig );
         pthread_rwlock_destroy( &lock );
         
         return -ENOMEM;
      }
   }
   
   // got all blocks; load the rest of the structure
   dest->volume_id = mmsg->volume_id();
   dest->coordinator_id = mmsg->coordinator_id();
   dest->file_id = mmsg->file_id();
   dest->file_version = mmsg->file_version();
   
   dest->size = mmsg->size();
   dest->owner_id = mmsg->owner_id();
   
   dest->mtime_sec = mmsg->mtime_sec();
   dest->mtime_nsec = mmsg->mtime_nsec();
   dest->stale = false;

   memcpy( sig, mmsg->signature().data(), mmsg->signature().size() );
   siglen = mmsg->signature().size();
   
   dest->blocks = blocks;
   dest->lock = lock;
   dest->signature = sig;
   dest->signature_len = siglen;
   
   return 0;
}


/**
 * @brief Load a manifest from a serialized bytestring that encodes a protobuf
 * @param[out] manifest Manifest to be populated
 * @retval 0 Success, and populate *manifest
 * @retval -EINVAL if it's not a valid protobuf
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_load_from_chunk( struct SG_manifest* manifest, struct SG_chunk* chunk ) {

   int rc = 0;
   SG_messages::Manifest proto_manifest;

   try {
      rc = md_parse< SG_messages::Manifest >( &proto_manifest, chunk->data, chunk->len );
   }
   catch( bad_alloc& ba ) {
      return -ENOMEM;
   }

   if( rc != 0 ) {
      SG_error("md_parse rc = %d\n", rc );
      return -EINVAL;
   }

   rc = SG_manifest_load_from_protobuf( manifest, &proto_manifest );
   if( rc != 0 ) {
      SG_error("SG_manifest_load_from_protobuf rc = %d\n", rc );
      return rc;
   }

   return rc;
}


/**
 * @brief Free a manifest block 
 * @note Always succeeds
 */
int SG_manifest_block_free( struct SG_manifest_block* block ) {
   
   SG_safe_free( block->hash );
   
   memset( block, 0, sizeof(struct SG_manifest_block) );
   return 0;
}


/**
 * @brief Free a manifest 
 * @note Always succeeds
 */
int SG_manifest_free( struct SG_manifest* manifest ) {
   
   if( manifest->blocks != NULL ) {
      
      SG_manifest_block_map_free( manifest->blocks );
      SG_safe_delete( manifest->blocks );
   }
   
   SG_safe_free( manifest->signature ); 
   pthread_rwlock_destroy( &manifest->lock );
   memset( manifest, 0, sizeof(struct SG_manifest) );
   return 0;
}


/**
 * @brief Free a block map 
 * @note Always succeeds
 */
int SG_manifest_block_map_free( SG_manifest_block_map_t* blocks ) {
   
   for( SG_manifest_block_map_t::iterator itr = blocks->begin(); itr != blocks->end(); itr++ ) {
      
      SG_manifest_block_free( &itr->second );
   }
   
   blocks->clear();
   return 0;
}


/**
 * @brief Set the manifest file version 
 * @note Manifest cannot be locked
 * @note Always succeeds
 */
int SG_manifest_set_file_version( struct SG_manifest* manifest, int64_t version ) {
   
   SG_manifest_wlock( manifest );
   
   manifest->file_version = version;
   
   SG_manifest_unlock( manifest );
   return 0;
}

/**
 * @brief Add a block to the manifest.
 *
    Duplicate the block if dup_block is true; otherwise the manifest takes ownership of all data within it (shallow-copied)
    If replace is true, then this block will be allowed to overwrite an existing block (which will then be freed)
    Otherwise, this method will return with -EEXIST if the given block is already present.
 * @note manifest cannot be locked
 * @note This is a zero-alloc operation if replace is true, dup_block is false, and the block already exists in the manifest (i.e. the data is just copied over, and the old data is freed)
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL The block is malformed
 * @retval -EEXIST If replace is false, but a block with the given ID is already present in the manifest
 */
static int SG_manifest_put_block_ex( struct SG_manifest* manifest, struct SG_manifest_block* block, bool replace, bool dup_block ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   // does this block exist, and if so, can we bail?
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block->block_id );
   if( itr != manifest->blocks->end() ) {
      
      if( !replace ) {
         // can't replace 
         SG_manifest_unlock( manifest );
         return -EEXIST;
      }
      
      struct SG_manifest_block oldblock = itr->second;
      SG_manifest_block_free( &itr->second );
      
      // replace
      if( dup_block ) {
         
         rc = SG_manifest_block_dup( &itr->second, block );
         
         if( rc != 0 ) {
            
            // OOM 
            itr->second = oldblock;
            SG_manifest_unlock( manifest );
            return rc;
         }
      }
      else {
         
         // replace
         struct SG_manifest_block old_block = itr->second;
         
         itr->second = *block;
         
         SG_manifest_block_free( &old_block );
      }
   }
   else {
      
      // no such block.  make one 
      struct SG_manifest_block *to_put = NULL;
      struct SG_manifest_block block_dup;
      
      if( dup_block ) {
         
         // duplicate
         memset( &block_dup, 0, sizeof(struct SG_manifest_block) );
         
         rc = SG_manifest_block_dup( &block_dup, block );
         if( rc != 0 ) {
            
            // OOM 
            SG_manifest_unlock( manifest );
            return rc;
         }
         
         to_put = &block_dup;
      }
      else {
         
         // put directly
         to_put = block;
      }
      
      try {
         
         // put in place (shallow-copy) 
         (*manifest->blocks)[ to_put->block_id ] = *to_put;
      }
      catch( bad_alloc& ba ) {
         
         // OOM 
         if( dup_block ) {
            SG_manifest_block_free( &block_dup );
         }
         
         SG_manifest_unlock( manifest );
         return -ENOMEM;
      }
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Add a block to the manifest, duplicating it in the process.
 *
    If replace is true, then this block will be allowed to overwrite an existing block (which will then be freed)
    otherwise, this method will return with -EEXIST if the given block is already present.
 * @note manifest cannot be locked
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL The block is malformed
 */
int SG_manifest_put_block( struct SG_manifest* manifest, struct SG_manifest_block* block, bool replace ) {
   
   return SG_manifest_put_block_ex( manifest, block, replace, true );
}


/**
 * @brief Put a block into the manifest directly
 *
 * If replace is true, then this block will be allowed to overwrite an existing block (which will then be freed)
 * @note manifest cannot be locked
 * @return Value of SG_manifest_put_block_ex(...)
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL if the block is malformed
 * @retval -EEXIST Already present
 * @see SG_manifest_put_block_ex
 */
int SG_manifest_put_block_nocopy( struct SG_manifest* manifest, struct SG_manifest_block* block, bool replace ) {
   
   return SG_manifest_put_block_ex( manifest, block, replace, false );
}


/**
 * @brief Delete a block from the manifest 
 * @retval 0 Success
 * @retval -ENOENT Not found.
 */
int SG_manifest_delete_block( struct SG_manifest* manifest, uint64_t block_id ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr == manifest->blocks->end() ) {
      
      rc = -ENOENT;
   }
   else {
      
      SG_manifest_block_free( &itr->second ); 
      manifest->blocks->erase( itr );
   }
   
   SG_manifest_unlock( manifest );
   
   return rc;
}


/**
 * @brief Patch a manifest 
 *
    Go through the blocks of src, and put them into dest.
    If replace is true, then the blocks of dest will overwrite existing blocks in src (which will then be freed)
    If dup_block is true, then blocks of src will be duplicated and put into dest.  Otherwise, they'll be placed in directly.
 * @note manifest cannot be locked 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL if the block was malformed 
 * @retval -EEXIST Failed
 */
static int SG_manifest_patch_ex( struct SG_manifest* dest, struct SG_manifest* src, bool replace, bool dup_block ) {

   int rc = 0;
   
   if( !replace ) {
      
      // verify that no blocks will be replaced 
      for( SG_manifest_block_map_t::iterator itr = src->blocks->begin(); itr != src->blocks->end(); itr++ ) {
         
         if( dest->blocks->find( itr->first ) != dest->blocks->end() ) {
            
            // will collide
            return -EEXIST;
         }
      }
   }
   
   for( SG_manifest_block_map_t::iterator itr = src->blocks->begin(); itr != src->blocks->end(); itr++ ) {
      
      rc = SG_manifest_put_block_ex( dest, &itr->second, replace, dup_block );
      if( rc != 0 ) {
         
         return rc;
      }
   }
   
   return rc;
}


/**
 * @brief Patch a manifest
 *
    Go through the blocks of src, duplicate them, and put the duplicates into dest.
    If replace is true, then the blocks of dest will overwrite existing blocks in src (which will then be freed)
 * @note manifest cannot be locked
 * @return The value of SG_manifest_patch_ex(...)
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL The block was malformed 
 * @retval -EEXIST Failed
 * @see SG_manifest_patch_ex
 */
int SG_manifest_patch( struct SG_manifest* dest, struct SG_manifest* src, bool replace ) {
   
   return SG_manifest_patch_ex( dest, src, replace, true );
}


/**
 * @brief Patch a manifest 
 *
    Go through the blocks of src, and put them directly into dest.  dest takes ownership of src's blocks.
    If replace is true, then the blocks of dest will overwrite existing blocks in src (which will then be freed)
 * @note manifest cannot be locked 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory 
 * @retval -EINVAL if the block was malformed 
 * @retval -EEXIST Failed
 * @see SG_manifest_patch_ex
 */
int SG_manifest_patch_nocopy( struct SG_manifest* dest, struct SG_manifest* src, bool replace ) {
   
   return SG_manifest_patch_ex( dest, src, replace, false );
}


/**
 * @brief Truncate a manifest
 *
 * If there are any blocks with a block ID larger than max_block_id, then remove them 
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_truncate( struct SG_manifest* manifest, uint64_t max_block_id ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   // find all blocks with IDs greater than max_block_id 
   SG_manifest_block_map_t::iterator base = manifest->blocks->upper_bound( max_block_id );
   SG_manifest_block_map_t::iterator itr = base;
   
   if( itr != manifest->blocks->end() ) {
      
      // remove them all 
      while( itr != manifest->blocks->end() ) {
         
         SG_manifest_block_free( &itr->second );
         itr++;
      }
      
      manifest->blocks->erase( base, manifest->blocks->end() );
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Set the dirty bit for a block 
 * @retval 0 Success
 * @retval -ENOENT if there is no such block
 */
int SG_manifest_set_block_dirty( struct SG_manifest* manifest, uint64_t block_id, bool dirty ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
      
      struct SG_manifest_block* block_info = &itr->second;
      
      block_info->dirty = dirty;
   }
   else {
      
      rc = -ENOENT;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Set the dirty bit for all blocks in a manifest 
 * @retval 0 Success
 */
int SG_manifest_set_blocks_dirty( struct SG_manifest* manifest, bool dirty ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   for( SG_manifest_block_map_t::iterator itr = manifest->blocks->begin(); itr != manifest->blocks->end(); itr++ ) {
      
      struct SG_manifest_block* block_info = &itr->second;
      
      block_info->dirty = dirty;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Set the modification time for the manifest
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_set_modtime( struct SG_manifest* manifest, int64_t mtime_sec, int32_t mtime_nsec ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   manifest->mtime_sec = mtime_sec;
   manifest->mtime_nsec = mtime_nsec;
   
   SG_manifest_unlock( manifest );
   return rc;
}

/**
 * @brief Set the owner ID of the manifest 
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_set_owner_id( struct SG_manifest* manifest, uint64_t owner_id ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   manifest->owner_id = owner_id;
   
   SG_manifest_unlock( manifest );
   
   return rc;
}

/**
 * @brief Set the coordinator ID of the manifest 
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_set_coordinator_id( struct SG_manifest* manifest, uint64_t coordinator_id ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   manifest->coordinator_id = coordinator_id;
   
   SG_manifest_unlock( manifest );
   
   return rc;
}

/**
 * @brief Set the size of the assocaited file 
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_set_size( struct SG_manifest* manifest, uint64_t size ) {
   
   int rc = 0;
   
   SG_manifest_wlock( manifest );
   
   manifest->size = size;
   
   SG_manifest_unlock( manifest );
   
   return rc;
}

/**
 * @brief Mark the manifest as stale 
 * @note Always succeeds 
 * @retval 0 Success
 */
int SG_manifest_set_stale( struct SG_manifest* manifest, bool stale ) {
   
   SG_manifest_wlock( manifest );
   
   manifest->stale = stale;
   
   SG_manifest_unlock( manifest );

   if( stale ) {
      SG_debug("%p: set stale\n", manifest);
   }

   return 0;
}

/**
 * @brief Get a manifest block's ID
 * @return block_id
 */
uint64_t SG_manifest_block_id( struct SG_manifest_block* block ) {
   return block->block_id;
}

/**
 * @brief Get a manifest block's version
 * @return block_version
 */ 
int64_t SG_manifest_block_version( struct SG_manifest_block* block ) {
   return block->block_version;
}

/**
 * @brief Get manifest block's type
 * @return type
 */
int SG_manifest_block_type( struct SG_manifest_block* block ) {
   return block->type;
}

/**
 * @brief Get a manifest block's dirty status
 * @return dirty
 */
bool SG_manifest_block_is_dirty( struct SG_manifest_block* block ) {
   return block->dirty;
}

/**
 * @brief Get a manifest block's hash
 * @return hash
 */ 
unsigned char* SG_manifest_block_hash( struct SG_manifest_block* block ) {
   return block->hash;
}

/**
 * @brief Set the block version
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_block_set_version( struct SG_manifest_block* block, int64_t version ) {
   block->block_version = version;
   return 0;
}

/**
 * @brief Set a manifest's block hash (freeing the previous one, if present)
 *
 * The block takes ownership of the hash
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_block_set_hash( struct SG_manifest_block* block, unsigned char* hash ) {
   if( block->hash != NULL ) {
      SG_safe_free( block->hash );
   }
   block->hash = hash;
   return 0;
}

/**
 * @brief Set the block logical write offset
 * @note Always succeeds
 * @retval 0 Success
 */
int SG_manifest_block_set_logical_write( struct SG_manifest_block* block, uint64_t offset, uint64_t len ) {
   block->logical_write_offset = offset;
   block->logical_write_len = len;
   return 0;
}

/**
 * @brief Get the block logical write offset
 * @return logical_write_offset
 */
uint64_t SG_manifest_block_get_logical_write_offset( struct SG_manifest_block* block ) {
   return block->logical_write_offset;
}

/**
 * @brief Get the block logical write length
 * @return logical_write_len
 */
uint64_t SG_manifest_block_get_logical_write_len( struct SG_manifest_block* block ) {
   return block->logical_write_len;
}


/**
 * @brief Get the manifest volume ID
 * @return volume_id
 */
uint64_t SG_manifest_get_volume_id( struct SG_manifest* manifest );
uint64_t SG_manifest_get_volume_id( struct SG_manifest* manifest ) {
   
   uint64_t volume_id = 0;
   
   SG_manifest_rlock( manifest );
   
   volume_id = manifest->volume_id;
   
   SG_manifest_unlock( manifest );
   
   return volume_id;
}

/**
 * @brief Get the manifest file ID
 * @return file_id
 */ 
uint64_t SG_manifest_get_file_id( struct SG_manifest* manifest ) {
   
   uint64_t file_id = 0;
   
   SG_manifest_rlock( manifest );
   
   file_id = manifest->file_id;
   
   SG_manifest_unlock( manifest );
   
   return file_id;
}


/**
 * @brief Get the manifest file version
 * @return file_version
 */ 
int64_t SG_manifest_get_file_version( struct SG_manifest* manifest ) {
   
   int64_t version = 0;
   
   SG_manifest_rlock( manifest );
   
   version = manifest->file_version;
   
   SG_manifest_unlock( manifest );
   
   return version;
}


/**
 * @brief Get the number of blocks *represented* by the manifest
 * @return the *maximum* block ID + 1
 */
uint64_t SG_manifest_get_block_range( struct SG_manifest* manifest ) {
   
   uint64_t rc = 0;
   
   SG_manifest_rlock( manifest );
   
   if( manifest->blocks->size() > 0 ) {
      
      SG_manifest_block_map_t::reverse_iterator ritr = manifest->blocks->rbegin();
      rc = ritr->first + 1;
   }
   
   SG_manifest_unlock( manifest );
   
   return rc;
}

/**
 * @brief Get the actual number of blocks in the manifest 
 * @return manifest->blocks->size()
 */
uint64_t SG_manifest_get_block_count( struct SG_manifest* manifest ) {
   
   uint64_t ret = 0;
   
   SG_manifest_rlock( manifest );
   
   ret = manifest->blocks->size();
   
   SG_manifest_unlock( manifest );
   
   return ret;
}
   
/**
 * @brief Get the size of the file
 * @return manifest->size
 */
uint64_t SG_manifest_get_file_size( struct SG_manifest* manifest ) {
   
   uint64_t ret = 0;
   
   SG_manifest_rlock( manifest );
   
   ret = manifest->size;
   
   SG_manifest_unlock( manifest );
   
   return ret;
}

/**
 * @brief Get a malloc'ed copy of a block's hash 
 *
 * If block_hash is NULL, it will be alloced.  Otherwise, it will be used.
 * param[out] *block_hash The hash
 * param[out] *hash_len The hash length
 * @retval 0 Success, and set *block_hash and *hash_len
 * @retval -ENOMEM Out of Memory 
 * @retval -ENOENT Not found
 * @retval -ERANGE *block_hash is not NULL, but is not big enough to hold the block's hash (*hash_len will be set to the required length)
 * @retval -ENODATA There is no hash for this (existant) block 
 */
int SG_manifest_get_block_hash( struct SG_manifest* manifest, uint64_t block_id, unsigned char** block_hash, size_t* hash_len ) {
   
   unsigned char* ret = NULL;
   int rc = 0;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
     
      if( itr->second.hash_len == 0 || itr->second.hash == NULL ) {
         // no hash 
         rc = -ENODATA;
      }
      else {
         if( *block_hash != NULL && itr->second.hash_len >= *hash_len * sizeof(unsigned char) ) {
            memcpy( *block_hash, itr->second.hash, itr->second.hash_len * sizeof(unsigned char) );
         }
         else if( *block_hash != NULL ) {

            rc = -ERANGE;
            *hash_len = itr->second.hash_len;
         }
         else {
             ret = SG_CALLOC( unsigned char, itr->second.hash_len );
         
             if( ret != NULL ) {
            
                memcpy( ret, itr->second.hash, sizeof(unsigned char) * itr->second.hash_len );
            
                *block_hash = ret;
                *hash_len = itr->second.hash_len;
             }
             else {
                rc = -ENOMEM;
             }
         }
      }
   }
   else {
      rc = -ENOENT;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Check if a block has a hash
 * @retval True Has a hash
 * @retval False No hash (including if it doesn't exist)
 */
bool SG_manifest_has_block_hash( struct SG_manifest* manifest, uint64_t block_id ) {

   bool rc = true;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
     
      if( itr->second.hash_len == 0 || itr->second.hash == NULL ) {
         // no hash 
         rc = -false;
      }
   }
   else {
      rc = false;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Get a block's version
 * @retval 0 Success 
 * @retval -ENOENT Not found
 */
int SG_manifest_get_block_version( struct SG_manifest* manifest, uint64_t block_id, int64_t* block_version ) {
   
   int rc = 0;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
      
      *block_version = itr->second.block_version;
   }
   else { 
      
      rc = -ENOENT;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Get the coordinator for this manifest 
 * @note Always succeeds
 */
uint64_t SG_manifest_get_coordinator( struct SG_manifest* manifest ) {
   
   uint64_t ret = 0;
   
   SG_manifest_rlock( manifest );
   
   ret = manifest->coordinator_id;
   
   SG_manifest_unlock( manifest );
   return ret;
}

/**
 * @brief Determine if a block is represented in the manifest.
 *
 * If it is not, it's a "block hole"
 * @retval True If it's present 
 * @retval False If it's a hole
 */
bool SG_manifest_is_block_present( struct SG_manifest* manifest, uint64_t block_id ) {
   
   bool ret = false;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   
   ret = (itr != manifest->blocks->end());
   
   SG_manifest_unlock( manifest );
   
   return ret;
}

/**
 * @brief Get a manifest's modtime, putting it into *mtime_sec and *mtime_nsec 
 * @note Always succeeds
 */
int SG_manifest_get_modtime( struct SG_manifest* manifest, int64_t* mtime_sec, int32_t* mtime_nsec ) {
   
   SG_manifest_rlock( manifest );
   
   *mtime_sec = manifest->mtime_sec;
   *mtime_nsec = manifest->mtime_nsec;
   
   SG_manifest_unlock( manifest );
   return 0;
}

/**
 * @brief Get the manifest's modtime, second half
 * @note Always succeeds
 */
int64_t SG_manifest_get_modtime_sec( struct SG_manifest* manifest ) {
   
   SG_manifest_rlock( manifest );
   
   int64_t mtime_sec = manifest->mtime_sec;
   
   SG_manifest_unlock( manifest );
   return mtime_sec;
}

/**
 * @brief Get the manifest's modtime, nanosecond half
 * @note Always succeeds
 */
int32_t SG_manifest_get_modtime_nsec( struct SG_manifest* manifest ) {

   SG_manifest_rlock( manifest );
   
   int32_t mtime_nsec = manifest->mtime_nsec;
   
   SG_manifest_unlock( manifest );
   return mtime_nsec;
}

/**
 * @brief Check if a manifest is stale
 * @retval True Stale
 * @retval False Not stale
 */
bool SG_manifest_is_stale( struct SG_manifest* manifest ) {
   
   bool ret = false;
   
   SG_manifest_rlock( manifest );
   
   ret = manifest->stale;
   
   SG_manifest_unlock( manifest );
   
   return ret;
}

/**
 * @brief Look up a block and return a pointer to it 
 * @note this pointer is only good for as long as no blocks are added or removed from the manifest!
 * @return Pointer to a block
 * @retval NULL The block is not known.
 */
struct SG_manifest_block* SG_manifest_block_lookup( struct SG_manifest* manifest, uint64_t block_id ) {
   
   struct SG_manifest_block* ret = NULL;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
      
      ret = &itr->second;
   }
   
   SG_manifest_unlock( manifest );
   
   return ret;
}


/**
 * @brief Look up and compare a block's hash against a test hash 
 * @retval 1 They are equal 
 * @retval 0 They are not equal 
 * @retval -ENOENT There is no block in this manifest 
 * @retval -ENODATA The block in the manifest does not have a hash 
 * @retval -EINVAL The hash length does not match the block's hash length
 */
int SG_manifest_block_hash_eq( struct SG_manifest* manifest, uint64_t block_id, unsigned char* test_hash, size_t test_hash_len ) {
   
   int rc = 0;
   
   SG_manifest_rlock( manifest );
   
   SG_manifest_block_map_t::iterator itr = manifest->blocks->find( block_id );
   if( itr != manifest->blocks->end() ) {
      
      struct SG_manifest_block* block = &itr->second;
      
      if( block->hash == NULL ) {
         
         // no hash 
         rc = -ENODATA;
      }
      else if( block->hash_len != test_hash_len ) {
         
         // differring lengths 
         rc = -EINVAL;
      }
      else {
         
         // compare!
         rc = memcmp( block->hash, test_hash, test_hash_len );
         if( rc == 0 ) {
            
            // equal 
            rc = 1;
         }
         else {
            
            // not equal 
            rc = 0;
         }
      }
   }
   else {
      
      // no block 
      rc = -ENOENT;
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}

/**
 * @brief Put a manifest's data into its protobuf representation 
 *
 * The manifest will NOT be signed
 * @note The caller should free mmsg regardless of the return code
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_serialize_to_protobuf( struct SG_manifest* manifest, SG_messages::Manifest* mmsg ) {
   
   int rc = 0;
   
   SG_manifest_rlock( manifest );

   // serialize all blocks 
   for( SG_manifest_block_map_t::iterator itr = manifest->blocks->begin(); itr != manifest->blocks->end(); itr++ ) {
      
      SG_messages::ManifestBlock* next_block = NULL;
      
      try {
         
         next_block = mmsg->add_blocks();
      }
      catch( bad_alloc& ba ) {
         
         rc = -ENOMEM;
         break;
      }
      
      rc = SG_manifest_block_serialize_to_protobuf( &itr->second, next_block );
      if( rc != 0 ) {
         break;
      }
   }
   
   if( rc == 0 ) {
      
      // serialize the rest of the manifest 
      mmsg->set_volume_id( manifest->volume_id );
      mmsg->set_coordinator_id( manifest->coordinator_id );
      mmsg->set_file_id( manifest->file_id );
      mmsg->set_file_version( manifest->file_version );
      
      mmsg->set_mtime_sec( manifest->mtime_sec );
      mmsg->set_mtime_nsec( manifest->mtime_nsec );
      
      mmsg->set_size( manifest->size );
      mmsg->set_owner_id( manifest->owner_id );

      if( manifest->signature != NULL ) {
         try {
            mmsg->set_signature( string(manifest->signature, manifest->signature_len) );
         }
         catch( bad_alloc& ba ) {
            return -ENOMEM;
         }
      }
      else {
         mmsg->set_signature( string("") );
      }
   }
      
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Put a manifest's block data into a request 
 * @retval 0 Success 
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_serialize_blocks_to_request_protobuf( struct SG_manifest* manifest, SG_messages::Request* request ) {
   
   int rc = 0;
   
   SG_manifest_rlock( manifest );
   
   for( SG_manifest_block_map_t::iterator itr = manifest->blocks->begin(); itr != manifest->blocks->end(); itr++ ) {
      
      SG_messages::ManifestBlock* next_block = NULL;
      
      try {
         
         next_block = request->add_blocks();
      }
      catch( bad_alloc& ba ) {
         
         rc = -ENOMEM;
         break;
      }
      
      rc = SG_manifest_block_serialize_to_protobuf( &itr->second, next_block );
      if( rc != 0 ) {
         break;
      }
   }
   
   SG_manifest_unlock( manifest );
   return rc;
}


/**
 * @brief Serialize a block to a protobuf 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_block_serialize_to_protobuf_ex( struct SG_manifest_block* block, SG_messages::ManifestBlock* mblock, bool include_logical_write_data ) {
  
   // sanity check...
   if( block->hash == NULL && block->hash_len != 0 ) {
     SG_error("BUG: block [%" PRIu64 ".%" PRId64 "] hash is NULL\n", block->block_id, block->block_version);
     exit(1);
   }
   try {
     
      if( block->hash != NULL ) { 
          mblock->set_hash( string((char*)block->hash, block->hash_len) );
      }
       
      mblock->set_block_id( block->block_id );
      mblock->set_block_version( block->block_version );

      if( block->type != 0 ) {
         mblock->set_chunk_type( block->type );
      }

      if( include_logical_write_data ) {
         mblock->set_logical_offset( block->logical_write_offset );
         mblock->set_logical_len( block->logical_write_len );
      }
   }
   catch( bad_alloc& ba ) {
      
      return -ENOMEM;
   }
   
   return 0;
}

/**
 * @brief Call SG_manifest_block_serialize_to_protobuf_ex()
 * @see SG_manifest_block_serialize_to_protobuf_ex
 */
int SG_manifest_block_serialize_to_protobuf( struct SG_manifest_block* block, SG_messages::ManifestBlock* mblock) {
   return SG_manifest_block_serialize_to_protobuf_ex( block, mblock, false );
}

/**
 * @brief Print out a manifest to stdout (i.e. for debugging)
 * @retval -ENOMEM Out of Memory
 */
int SG_manifest_print( struct SG_manifest* manifest ) {
   
   SG_manifest_rlock( manifest );
   
   printf("Manifest: /%" PRIu64 "/%" PRIX64 ".%" PRId64 ".%" PRId64 ".%d, coordinator=%" PRIu64 ", owner=%" PRIu64 ", size=%" PRIu64 "\n",
           manifest->volume_id, manifest->file_id, manifest->file_version, manifest->mtime_sec, manifest->mtime_nsec, manifest->coordinator_id, manifest->owner_id, manifest->size );
   
   for( SG_manifest_block_map_t::iterator itr = manifest->blocks->begin(); itr != manifest->blocks->end(); itr++ ) {
      
      char* hash_printable = NULL;
      char const* type_str = NULL;

      hash_printable = md_data_printable( itr->second.hash, itr->second.hash_len );
      if( hash_printable == NULL ) {
         return -ENOMEM;
      }
      
      if( itr->second.type == SG_MANIFEST_BLOCK_TYPE_MANIFEST ) {
         type_str = "manifest";
      }
      else if( itr->second.type == SG_MANIFEST_BLOCK_TYPE_BLOCK ) {
         type_str = "block";
      }
      else {
         type_str = "UNKNOWN";
      }

      printf("  Block (type=%s) %" PRIu64 ".%" PRId64 " hash=%s\n", type_str, itr->first, itr->second.block_version, hash_printable );
      
      SG_safe_free( hash_printable );
   }
   
   return 0;
}
