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
 * @file libsyndicate-ug/core.cpp
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief User Gateway core related functions
 *
 * @see libsyndicate-ug/core.h
 */

#include "core.h"
#include "client.h"
#include "impl.h"
#include "fs.h"
#include "vacuumer.h"

#define UG_DRIVER_NUM_ROLES  3
#define UG_DRIVER_NUM_INSTANCES 3
char const* UG_DRIVER_ROLES[ UG_DRIVER_NUM_ROLES ] = {
   "cdn_url",
   "serialize",
   "deserialize"
};

/// Global UG state
struct UG_state {
   
   struct SG_gateway* gateway;          ///< Reference to the gateway core (which, in turn, points to UG_state)
   
   uint64_t* replica_gateway_ids;       ///< IDs of replica gateways to replicate data to
   size_t num_replica_gateway_ids;
   
   struct fskit_core* fs;               ///< Filesystem core 
   
   struct UG_vacuumer* vacuumer;        ///< Vacuumer instance 
   
   pthread_rwlock_t lock;               ///< Lock governing access to this structure
  
   // fskit route handles
   int stat_rh;                         ///< fskit route handle 
   int creat_rh;                        ///< fskit route handle 
   int mkdir_rh;                        ///< fskit route handle 
   int open_rh;                         ///< fskit route handle 
   int read_rh;                         ///< fskit route handle  
   int write_rh;                        ///< fskit route handle  
   int trunc_rh;                        ///< fskit route handle 
   int close_rh;                        ///< fskit route handle 
   int sync_rh;                         ///< fskit route handle 
   int detach_rh;                       ///< fskit route handle 
   int rename_rh;                       ///< fskit route handle 
   int getxattr_rh;                     ///< fskit route handle 
   int setxattr_rh;                     ///< fskit route handle 
   int removexattr_rh;                  ///< fskit route handle 
   int listxattr_rh;                    ///< fskit route handle 
   
   bool running_thread;                 ///< If true, we've set up and started a thread to run the main loop ourselves 
   pthread_t thread;                    ///< The main loop thread
   
   struct md_wq* wq;                    ///< Workqueue for deferred operations (like blowing away dead inodes)

   void* cls;                           ///< Extra UG-implementation state
};


/// RG request context 
struct UG_RG_context {

   uint64_t* rg_ids;
   int* rg_status;
   size_t num_rgs;
};


/**
 * @brief Create a duplicate listing of the replica gateway IDs 
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int UG_state_list_replica_gateway_ids( struct UG_state* state, uint64_t** replica_gateway_ids, size_t* num_replica_gateway_ids ) {
   
   uint64_t* ret = NULL;
   
   UG_state_rlock( state );
   
   ret = SG_CALLOC( uint64_t, state->num_replica_gateway_ids );
   if( ret == NULL ) {
      
      UG_state_unlock( state );
      return -ENOMEM;
   }
   
   memcpy( ret, state->replica_gateway_ids, sizeof(uint64_t) * state->num_replica_gateway_ids );
   
   *replica_gateway_ids = ret;
   *num_replica_gateway_ids = state->num_replica_gateway_ids;
   
   UG_state_unlock( state );
   
   return 0;
}


/**
 * @brief Get the number of RGs we know about
 * @return Number of RGs
 */
size_t UG_state_num_replica_gateways( struct UG_state* state ) {
   UG_state_rlock(state);
   size_t ret = state->num_replica_gateway_ids;
   UG_state_unlock(state);
   return ret;
}


/**
 * @brief Reload the set of replica gateway IDs from the MS
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 */
int UG_state_reload_replica_gateway_ids( struct UG_state* state ) {
   
   int rc = 0;
   
   uint64_t* replica_gateway_ids = NULL;
   size_t num_replica_gateway_ids = 0;
   
   struct SG_gateway* gateway = UG_state_gateway( state );
   struct ms_client* ms = SG_gateway_ms( gateway );
   
   // find all replica gateways
   rc = ms_client_get_gateways_by_type( ms, SYNDICATE_RG, &replica_gateway_ids, &num_replica_gateway_ids );
   if( rc != 0 ) {
      
      return rc;
   }
   
   UG_state_wlock( state );
   
   SG_safe_free( state->replica_gateway_ids );
   
   state->replica_gateway_ids = replica_gateway_ids;
   state->num_replica_gateway_ids = num_replica_gateway_ids;

   SG_debug("%s", "RG IDs are:\n");
   for( size_t i = 0; i < num_replica_gateway_ids; i++ ) {
      SG_debug("   %" PRIu64 "\n", replica_gateway_ids[i] );
   }
   
   UG_state_unlock( state );
   
   return 0;
}


/**
 * @brief Make an RG context
 *
 * Calloc a struct UG_RG_context
 */
struct UG_RG_context* UG_RG_context_new() {
   return SG_CALLOC( struct UG_RG_context, 1 );
}

/**
 * @brief Set up an RG context
 * @param[out] *rctx Populate an RG context
 * @retval 0 Success
 * @retval -ENOMEM Out of Memory
 * @retval -EPERM Error
 */
int UG_RG_context_init( struct UG_state* state, struct UG_RG_context* rctx ) {

   int rc = 0;
   memset( rctx, 0, sizeof( struct UG_RG_context ) );

   // get RGs 
   rc = UG_state_list_replica_gateway_ids( state, &rctx->rg_ids, &rctx->num_rgs );
   if( rc != 0 ) {
     
      SG_error("UG_state_list_replica_gateway_ids rc = %d\n", rc ); 
      return rc;
   }

   rctx->rg_status = SG_CALLOC( int, rctx->num_rgs );
   if( rc != 0 ) {

      rc = -ENOMEM;
      UG_RG_context_free( rctx );
      return rc;
   }

   return 0;
}


/**
 * @brief Free an RG context's memory
 */ 
int UG_RG_context_free( struct UG_RG_context* rctx ) {

   if( rctx != NULL ) {
       SG_safe_free( rctx->rg_status );
       SG_safe_free( rctx->rg_ids );
       memset( rctx, 0, sizeof(struct UG_RG_context) );
   }
   return 0;
}


/**
 * @brief Get the RG IDs
 * @return rctx->rg_ids
 */
uint64_t* UG_RG_context_RG_ids( struct UG_RG_context* rctx ) {
   return rctx->rg_ids;
}

/**
 * @brief Get the number of RGs
 * @return rctx->num_rgs
 */
size_t UG_RG_context_num_RGs( struct UG_RG_context* rctx ) {
   return rctx->num_rgs;
}

/**
 * @brief Get the status of a particular RG RPC
 * @param[in] *rctx The RG context
 * @param[in] i The index of RG status
 * @return rctx->rg_status[i]
 */
int UG_RG_context_get_status( struct UG_RG_context* rctx, int i ) {
   return rctx->rg_status[i];
}

/**
 * @brief Set the status of a particular RG RPC
 * @param[in] *rctx The RG context
 * @param[in] i The index of RG status
 * @param[in] status The context status to be set
 * @return 0
 */
int UG_RG_context_set_status( struct UG_RG_context* rctx, int i, int status ) {
   rctx->rg_status[i] = status;
   return 0;
}

/**
 * @brief Send a request (controlplane/dataplane) to all RGs.
 *
 * Individual RG statuses will be recorded in rctx.
 * @retval 0 All requests succeeded
 * @retval -EPERM At least one request failed
 */
int UG_RG_send_all( struct SG_gateway* gateway, struct UG_RG_context* rctx, SG_messages::Request* controlplane_request, struct SG_client_request_async* datareq ) {

   int rc = 0;
   size_t i = 0;
   struct md_download_loop* dlloop = NULL;
   struct md_download_context* dlctx = NULL;
   int num_started = 0;
   int num_finished = 0;
   SG_messages::Reply reply;
   map< struct md_download_context*, int > download_idxs;

   dlloop = md_download_loop_new();
   if( dlloop == NULL ) {
      return -ENOMEM;
   }

   rc = md_download_loop_init( dlloop, SG_gateway_dl( gateway ), rctx->num_rgs );
   if( rc != 0 ) {

      SG_error("md_download_loop_init rc = %d\n", rc );
      SG_safe_free( dlloop );
      return rc;
   }

   for( i = 0; i < rctx->num_rgs; i++ ) {
      rctx->rg_status[i] = UG_RG_REQUEST_NOT_STARTED;
   }

   SG_debug("Send to %zu RGs\n", rctx->num_rgs );

   // try to send to each RG 
   do {
 
       // start sending to the next UG_RG_REQUEST_NOT_STARTED-tagged RG 
       for( i = 0; i < rctx->num_rgs; i++ ) {

           if( rctx->rg_status[i] == UG_RG_REQUEST_NOT_STARTED ) {
              
               rc = md_download_loop_next( dlloop, &dlctx );
               if( rc == 0 ) { 

                  SG_debug("RG request %" PRIu64 ": %p\n", rctx->rg_ids[i], dlctx );
               
                  try {
                     download_idxs[dlctx] = i;
                  }
                  catch( bad_alloc& ba ) {
                     rc = -ENOMEM;
                     break;
                  }

                  rc = SG_client_request_send_async( gateway, rctx->rg_ids[i], controlplane_request, datareq, dlloop, dlctx );
                  if( rc != 0 ) {

                     SG_error("SG_client_request_send_async(to %" PRIu64 ") rc = %d\n", rctx->rg_ids[i], rc );
                     break;
                  }

                  rctx->rg_status[i] = UG_RG_REQUEST_IN_PROGRESS;
                  num_started++;
                  continue;
               }
               else if( rc == -EAGAIN ) {
                  rc = 0;
                  break;
               }
               else {
                  // fatal error 
                  SG_error("md_download_loop_next(%p) rc = %d\n", dlloop, rc );
                  break;
               }
           }
       }

       // run until at least one finishes 
       rc = md_download_loop_run( dlloop );
       if( rc < 0 ) {

          SG_error("md_download_loop_run rc = %d\n", rc );
          break;
       }
       rc = 0;

       while( 1 ) {

           // next finished
           rc = md_download_loop_finished( dlloop, &dlctx );
           if( rc == 0 ) {

             // one finished
             rc = SG_client_request_send_finish( gateway, dlctx, &reply );
             if( rc != 0 ) {
         
                 SG_error("SG_client_request_send_finish rc = %d\n", rc );
                 break;
             }

             num_finished++;

             auto itr = download_idxs.find( dlctx );
             if( itr == download_idxs.end() ) {

                SG_error("BUG: no download context %p\n", dlctx );
                exit(1);
             }

             i = itr->second;

             // did the request succeed?
             if( reply.error_code() != 0 ) {

                SG_error("RG request %p failed: %d\n", dlctx, reply.error_code());
                rc = reply.error_code();

                rctx->rg_status[i] = -abs(rc);
                break;
             }
             else {

                rctx->rg_status[i] = UG_RG_REQUEST_SUCCESS;
             }
           }
        
           else if( rc == -EAGAIN ) {

              // all finished 
              rc = 0;
              break;
           }
           else {

              // error 
              SG_error("md_download_loop_finished rc = %d\n", rc );
              break;
           }
       }

       if( rc != 0 ) {
          break;
       }

       SG_debug("%d started, %d finished\n", num_started, num_finished );

   } while( md_download_loop_running( dlloop ) || (unsigned)num_finished < rctx->num_rgs );

   if( rc != 0 ) {
      
      // request failed failed. terminate.
      SG_error("Terminating RG requests, rc = %d\n", rc );
      md_download_loop_abort( dlloop );

      rc = -EIO;
   }

   md_download_loop_cleanup( dlloop, NULL, NULL );
   md_download_loop_free( dlloop );
   SG_safe_free( dlloop );

   return rc;

}


/**
 * @brief Read-lock state
 * @retval 0 Success
 */
int UG_state_rlock( struct UG_state* state ) {
   return pthread_rwlock_rdlock( &state->lock );
}

/**
 * @brief Write-lock state
 * @retval 0 Success
 */
int UG_state_wlock( struct UG_state* state ) {
   return pthread_rwlock_wrlock( &state->lock );
}

/**
 * @brief Unlock state
 * @retval 0 Success
 */
int UG_state_unlock( struct UG_state* state ) {
   return pthread_rwlock_unlock( &state->lock );
}


/**
 * @brief Easy way to set up the UG 
 * @return A UG on success
 * @retval NULL Error
 */
struct UG_state* UG_init( int argc, char** argv ) {
   
   struct UG_state* state = NULL;
   struct md_opts* overrides = md_opts_new( 1 );
   if( overrides == NULL ) {
      return NULL;
   }

   md_opts_default( overrides );
   md_opts_set_gateway_type( overrides, SYNDICATE_UG );
   md_opts_set_driver_config( overrides, UG_DEFAULT_DRIVER_EXEC_STR, UG_DRIVER_ROLES, UG_DRIVER_NUM_INSTANCES, UG_DRIVER_NUM_ROLES );
   
   state = UG_init_ex( argc, argv, overrides, NULL );

   md_opts_free( overrides );
   SG_safe_free( overrides );

   fskit_set_debug_level(2);
   return state;
}


/**
 * @brief Set up the UG, but with a set of behavior and type overrides 
 * @retval A UG on success
 * @retval NULL Error
 */
struct UG_state* UG_init_ex( int argc, char** argv, struct md_opts* overrides, void* cls ) {
   
   int rc = 0;
   struct md_entry root_inode_data;
   struct fskit_entry* fs_root = NULL;
   struct UG_inode* root_inode = NULL;
   struct UG_vacuumer* vacuumer = NULL;
   struct md_wq* wq = NULL;
   struct md_syndicate_conf* conf = NULL;
   struct SG_gateway* gateway = NULL;
   
   struct UG_state* state = SG_CALLOC( struct UG_state, 1 );
   if( state == NULL ) {
      
      return NULL;
   }

   state->stat_rh = -1;
   state->creat_rh = -1;
   state->mkdir_rh = -1;
   state->open_rh = -1;
   state->read_rh = -1;
   state->write_rh = -1;
   state->trunc_rh = -1;
   state->close_rh = -1;
   state->sync_rh = -1;
   state->detach_rh = -1;
   state->rename_rh = -1;
   
   gateway = SG_gateway_new();
   if( gateway == NULL ) {
      
      SG_safe_free( state );
      return NULL;
   }

   state->gateway = gateway;
   SG_gateway_set_cls( gateway, (void*)state );

   SG_debug("%s", "Activating filesystem\n");
   
   // set up fskit library...
   rc = fskit_library_init();
   if( rc != 0 ) {
      
      fskit_error( "fskit_library_init rc = %d\n", rc );
      SG_safe_free( state );
      SG_safe_free( gateway );
      return NULL;
   }
   
   rc = pthread_rwlock_init( &state->lock, NULL );
   if( rc != 0 ) {
      
      fskit_library_shutdown();
      SG_safe_free( state );
      SG_safe_free( gateway );
      return NULL;
   }
   
   SG_debug("%s", "Setting up gateway core\n");
   
   // set up gateway...
   rc = SG_gateway_init( state->gateway, md_opts_get_gateway_type( overrides ), argc, argv, overrides );
   if( rc < 0 ) {
      
      SG_error("SG_gateway_init rc = %d\n", rc );
      
      pthread_rwlock_destroy( &state->lock );
      fskit_library_shutdown();
      SG_safe_free( state );
      SG_safe_free( gateway );
      return NULL;
   }
   
   if( rc > 0 ) {
      
      // help was requested 
      md_common_usage();
      pthread_rwlock_destroy( &state->lock );
      fskit_library_shutdown();
      SG_safe_free( state );
      SG_safe_free( gateway );
      return NULL;
   }
   
   // debugging?
   conf = SG_gateway_conf( state->gateway );
   
   if( conf->debug_lock ) {
       
       SG_debug("%s\n", "Enable inode lock debugging");
       fskit_set_debug_level( 2 );
   }
   else if( md_get_debug_level() != 0 ) {
       
       fskit_set_debug_level( 1 );
   }
   else {
       
       fskit_set_debug_level( 0 );
   }
   
   SG_debug("%s", "Setting up filesystem core\n");
   
   // set up fs...
   state->fs = fskit_core_new();
   if( state->fs == NULL ) {
      
      // OOM
      pthread_rwlock_destroy( &state->lock );
      fskit_library_shutdown();
      SG_gateway_shutdown( gateway );
      SG_safe_free( gateway );
      SG_safe_free( state );
      return NULL;
   }
   
   rc = fskit_core_init( state->fs, state->gateway );
   if( rc != 0 ) {
      
      SG_error("fskit_core_init rc = %d\n", rc );
      
      SG_gateway_shutdown( gateway );
      SG_safe_free( gateway );
      pthread_rwlock_destroy( &state->lock );
      fskit_library_shutdown();
      SG_safe_free( state->fs );
      SG_safe_free( state );
      return NULL;
   }
   
   SG_debug("%s", "Looking up volume root\n");
   
   // set up root inode
   rc = ms_client_get_volume_root( SG_gateway_ms( state->gateway ), 0, 0, &root_inode_data );
   if( rc != 0 ) {
      
      SG_error("ms_client_get_volume_root() rc = %d\n", rc );
      UG_shutdown( state );
      
      return NULL;
   }
   
   root_inode = UG_inode_alloc( 1 );
   if( root_inode == NULL ) {
      
      // OOM 
      UG_shutdown( state );
      md_entry_free( &root_inode_data );
      return NULL;
   }
   
   SG_debug("%s", "Initializing root inode\n");
   
   // install root inode data
   fs_root = fskit_core_resolve_root( state->fs, true );
   if( fs_root == NULL ) {
      
      // something's seriously wrong 
      SG_error("fskit_entry_resolve_root rc = %p\n", fs_root );
      UG_shutdown( state );
      
      SG_safe_free( root_inode );
      md_entry_free( &root_inode_data );
      return NULL;
   }
   
   fskit_entry_set_owner( fs_root, root_inode_data.owner );
   fskit_entry_set_group( fs_root, root_inode_data.volume );
   fskit_entry_set_size( fs_root, root_inode_data.size );
   
   rc = UG_inode_init_from_export( root_inode, &root_inode_data, fs_root );
   if( rc == 0 ) {
      
      UG_inode_bind_fskit_entry( root_inode, fs_root );
   }
   else {
      
      // OOM or invalid 
      SG_error("UG_inode_init_from_export('/') rc = %d\n", rc );
      
      fskit_entry_unlock( fs_root );
      UG_shutdown( state );
      SG_safe_free( root_inode );
      md_entry_free( &root_inode_data );
      
      return NULL;
   }
   
   //////////////////////////////////////////////////////
   /*
   char* root_str = NULL;
   rc = md_entry_to_string( &root_inode_data, &root_str );
   if( rc == 0 ) {
      SG_debug("root:\n%s\n", root_str );
      SG_safe_free( root_str );
   }
   rc = 0;
   */
   //////////////////////////////////////////////////////
   
   fskit_entry_unlock( fs_root );
   md_entry_free( &root_inode_data );
   
   SG_debug("%s", "Setting up filesystem callbacks\n");
   
   // install methods 
   UG_impl_install_methods( state->gateway );
   UG_fs_install_methods( state->fs, state );
   
   // load replica gateways 
   rc = UG_state_reload_replica_gateway_ids( state );
   if( rc != 0 ) {
      
      UG_shutdown( state );
      return NULL;
   }
   
   SG_debug("%s", "Setting up deferred workqueue\n");
   
   // set up deferred workqueue 
   wq = md_wq_new( 1 );
   if( wq == NULL ) {
      
      UG_shutdown( state );
      return NULL;
   }
  
   rc = md_wq_init(wq, NULL);
   if( rc != 0 ) {
      UG_shutdown(state);
      SG_safe_free(wq);
      return NULL;
   }

   state->wq = wq;
   
   SG_debug("%s", "Starting vacuumer\n");
   
   // set up vacuumer 
   vacuumer = UG_vacuumer_new();
   if( vacuumer == NULL ) {

      UG_shutdown( state );
      return NULL;
   }

   state->vacuumer = vacuumer;
   rc = UG_vacuumer_init( state->vacuumer, state->gateway );
   if( rc != 0 ) {
      
      UG_shutdown( state );
      return NULL;
   }
   
   rc = UG_vacuumer_start( state->vacuumer );
   if( rc != 0 ) {
   
      UG_shutdown( state );
      return NULL;
   }
  
   SG_debug("%s", "Starting deferred workqueue\n");
   
   rc = md_wq_start( state->wq );
   if( rc != 0 ) {
      
      UG_shutdown( state );
      return NULL;
   }

   state->cls = cls;

   return state;
}


/**
 * @brief Main loop wrapper for pthreads
 */
void* UG_main_pthread( void* arg ) {
   
   struct UG_state* state = (struct UG_state*)arg;
   
   int rc = UG_main( state );
   if( rc != 0 ) {
      
      SG_error("UG_main rc = %d\n", rc );
   }
   
   return NULL;
}


/**
 * @brief Run the UG in a separate thread.
 *
 * Returns as soon as we start the new thread.
 * @retval 0 Success
 * @retval -EINVAL Already started the UG
 * @retval -ENOMEM Out of Memory 
 * @retval -errno Failure to fork
 */
int UG_start( struct UG_state* state ) {
   
   int rc = 0;
   
   if( state->running_thread ) {
      return -EINVAL;
   }
   
   rc = md_start_thread( &state->thread, UG_main_pthread, state, false );
   if( rc < 0 ) {
      
      return -EPERM;
   }
   
   state->running_thread = true;
   return 0;
}


/**
 * @brief Run the gateway in this thread
 *
 * Return when the gateway shuts down.
 * @retval 0 Success
 * @retval -errno Failure to initialize, or due to runtime error
 */
int UG_main( struct UG_state* state ) {
   
   int rc = 0;
   
   rc = SG_gateway_main( state->gateway );
   
   return rc;
}


/**
 * @brief Shut down the UG, given a state bundle passed from UG_init
 * @return 0
 */
int UG_shutdown( struct UG_state* state ) {
   
   int rc = 0;
   
   // are we running our own thread?  stop it if so.
   if( state->running_thread ) {
      
      SG_debug("%s", "Stopping main thread\n");
      
      SG_gateway_signal_main( UG_state_gateway( state ) );
      
      pthread_join( state->thread, NULL );
      state->running_thread = false;
   }
   
   // stop taking requests
   if( state->fs != NULL ) {
   
      SG_debug("%s", "Deactivating filesystem\n");
      UG_fs_uninstall_methods( state->fs );
   }
   
   // stop the vacuumer
   if( state->vacuumer != NULL ) {
   
       SG_debug("%s", "Quiesce vacuuming\n");
       UG_vacuumer_quiesce( state->vacuumer );
       UG_vacuumer_wait_all( state->vacuumer ); 
      
       SG_debug("%s", "Shut down vacuuming\n");
       UG_vacuumer_stop( state->vacuumer );
       UG_vacuumer_shutdown( state->vacuumer );
       SG_safe_free( state->vacuumer );
   }
   
   // stop the deferred workqueue 
   if( state->wq != NULL ) {
      md_wq_stop( state->wq );
      md_wq_free( state->wq, NULL );
      SG_safe_free( state->wq );
   }
   
   // prepare to shutdown 
   if( state->fs != NULL ) {
       UG_fs_install_shutdown_methods( state->fs );
   }

   if( state->gateway != NULL ) {
   
       SG_debug("%s", "Gateway shutdown\n");
       // destroy the gateway 
       rc = SG_gateway_shutdown( state->gateway );
       if( rc != 0 ) {
          SG_error("SG_gateway_shutdown rc = %d\n", rc );
       }

       SG_safe_free( state->gateway );
       state->gateway = NULL;
   }
   
   if( state->fs != NULL ) {
   
       SG_debug("%s", "Free all cached inodes\n");

       // blow away all inode data
       rc = fskit_detach_all( state->fs, "/" );
       if( rc != 0 ) {
          SG_error( "fskit_detach_all('/') rc = %d\n", rc );
       }
   
       SG_debug("%s", "Filesystem core shutdown\n");
   
       // destroy the core and its root inode
       rc = fskit_core_destroy( state->fs, NULL );
       if( rc != 0 ) {
          SG_error( "fskit_core_destroy rc = %d\n", rc );
       }
       
       SG_safe_free( state->fs );
   }
   
   SG_safe_free( state->replica_gateway_ids );
   
   pthread_rwlock_destroy( &state->lock );
   
   memset( state, 0, sizeof(struct UG_state) );

   SG_debug("%s", "Library shutdown\n");
   
   SG_safe_free( state );
   fskit_library_shutdown();
   
   return 0;
}

/**
 * @brief Get a pointer to the gateway core
 * @return state->gateway
 */
struct SG_gateway* UG_state_gateway( struct UG_state* state ) {
   return state->gateway;
}
   
/**
 * @brief Get a pointer to the filesystem core
 * @return state->fs
 */
struct fskit_core* UG_state_fs( struct UG_state* state ) {
   return state->fs;
}

/**
 * @brief Get a pointer to the vacuumer core
 * @return state->vacuumer
 */
struct UG_vacuumer* UG_state_vacuumer( struct UG_state* state ) {
   return state->vacuumer;
}

/**
 * @brief Get the owner ID of the gateway
 *
 * @see SG_gateway_user_id
 */
uint64_t UG_state_owner_id( struct UG_state* state ) {
   return SG_gateway_user_id( UG_state_gateway( state ) );
}

/**
 * @brief Get the volume ID of the gateway
 * @see ms_client_get_volume_id
 */
uint64_t UG_state_volume_id( struct UG_state* state ) {
   return ms_client_get_volume_id( SG_gateway_ms( UG_state_gateway( state ) ) );
}

/**
 * @brief Get the deferred workqueue
 * @return state->wq
 */
struct md_wq* UG_state_wq( struct UG_state* state ) {
   return state->wq;
}

/**
 * @brief Get a ref to the UG driver
 *
 * Call only when at least read-locked
 * @see SG_gateway_driver
 */
struct SG_driver* UG_state_driver( struct UG_state* state ) {
   return SG_gateway_driver( state->gateway );
}

/**
 * @brief Get UG implementation state 
 * @return state->cls
 */
void* UG_state_cls( struct UG_state* state ) {
   return state->cls;
}

/**
 * @brief Get stat route handle
 * @return state->stat_rh
 */
int UG_state_stat_rh( struct UG_state* state ) {
   return state->stat_rh;
}

/**
 * @brief Get creat route handle
 * @return state->creat_rh
 */
int UG_state_creat_rh( struct UG_state* state ) {
   return state->creat_rh;
}

/**
 * @brief Get mkdir route handle
 * @return state->mkdir_rh
 */
int UG_state_mkdir_rh( struct UG_state* state ) {
   return state->mkdir_rh;
}

/**
 * @brief Get open route handle
 * @return state->open_rh
 */
int UG_state_open_rh( struct UG_state* state ) {
   return state->open_rh;
}

/**
 * @brief Get read route handle
 * @return state->read_rh
 */
int UG_state_read_rh( struct UG_state* state ) {
   return state->read_rh;
}

/**
 * @brief Get write route handle
 * @return state->write_rh
 */
int UG_state_write_rh( struct UG_state* state ) {
   return state->write_rh;
}

/**
 * @brief Get trunc route handle
 * @return state->trunc_rh
 */
int UG_state_trunc_rh( struct UG_state* state ) {
   return state->trunc_rh;
}

/**
 * @brief Get close route handle 
 * @return state->close_rh
 */
int UG_state_close_rh( struct UG_state* state ) {
   return state->close_rh;
}

/**
 * @brief Get sync route handle
 * @return state->sync_rh
 */
int UG_state_sync_rh( struct UG_state* state ) {
   return state->sync_rh;
}

/**
 * @brief Get detach route handle
 * @return state->detach_rh
 */
int UG_state_detach_rh( struct UG_state* state ) {
   return state->detach_rh;
}

/**
 * @brief Get rename route handle
 * @return state->rename_rh
 */
int UG_state_rename_rh( struct UG_state* state ) {
   return state->rename_rh;
}

/**
 * @brief Get getxattr route handle
 * @return state->getxattr_rh
 */
int UG_state_getxattr_rh( struct UG_state* state ) {
   return state->getxattr_rh;
}

/**
 * @brief Get setxattr route handle
 * @return state->setxattr_rh
 */
int UG_state_setxattr_rh( struct UG_state* state ) {
   return state->setxattr_rh;
}

/**
 * @brief Get listxattr route handle
 * @return state->listxattr_rh
 */
int UG_state_listxattr_rh( struct UG_state* state ) {
   return state->listxattr_rh;
}

/**
 * @brief Get removexattr route handle
 * @return state->removexattr_rh
 */
int UG_state_removexattr_rh( struct UG_state* state ) {
   return state->removexattr_rh;
}

/**
 * @brief Set UG implementation state
 * @attention UG_state must be write-locked!
 */
void UG_state_set_cls( struct UG_state* state, void* cls ) {
   state->cls = cls;
}

/**
 * @brief Set stat route handle
 * @return 0
 */
int UG_state_set_stat_rh( struct UG_state* state, int rh ) {
   state->stat_rh = rh;
   return 0;
}

/**
 * @brief Set creat route handle
 * @return 0
 */
int UG_state_set_creat_rh( struct UG_state* state, int rh ) {
   state->creat_rh = rh;
   return 0;
}

/**
 * @brief Set mkdir route handle
 * @return 0
 */
int UG_state_set_mkdir_rh( struct UG_state* state, int rh ) {
   state->mkdir_rh = rh;
   return 0;
}

/**
 * @brief Set open route handle
 * @return 0
 */
int UG_state_set_open_rh( struct UG_state* state, int rh ) {
   state->open_rh = rh;
   return 0;
}

/**
 * @brief Set read route handle
 * @return 0
 */
int UG_state_set_read_rh( struct UG_state* state, int rh ) {
   state->read_rh = rh;
   return 0;
}

/**
 * @brief Set write route handle
 * @return 0
 */
int UG_state_set_write_rh( struct UG_state* state, int rh ) {
   state->write_rh = rh;
   return 0;
}

/**
 * @brief Set trunc route handle 
 * @return 0
 */
int UG_state_set_trunc_rh( struct UG_state* state, int rh ) {
   state->trunc_rh = rh;
   return 0;
}

/**
 * @brief Set close route handle 
 * @return 0
 */
int UG_state_set_close_rh( struct UG_state* state, int rh ) {
   state->close_rh = rh;
   return 0;
}

/**
 * @brief Set sync route handle
 * @return 0
 */
int UG_state_set_sync_rh( struct UG_state* state, int rh ) {
   state->sync_rh = rh;
   return 0;
}

/**
 * @brief Set detach route handle
 * @return 0
 */
int UG_state_set_detach_rh( struct UG_state* state, int rh ) {
   state->detach_rh = rh;
   return 0;
}

/**
 * @brief Set rename route handle
 * @return 0
 */
int UG_state_set_rename_rh( struct UG_state* state, int rh ) {
   state->rename_rh = rh;
   return 0;
}

/**
 * @brief Set getxattr route handle 
 * @return 0
 */
int UG_state_set_getxattr_rh( struct UG_state* state, int rh ) {
   state->getxattr_rh = rh;
   return 0;
}

/**
 * @brief Set setxattr route handle 
 * @return 0
 */
int UG_state_set_setxattr_rh( struct UG_state* state, int rh ) {
   state->setxattr_rh = rh;
   return 0;
}

/**
 * @brief Set listxattr route handle 
 * @return 0
 */
int UG_state_set_listxattr_rh( struct UG_state* state, int rh ) {
   state->listxattr_rh = rh;
   return 0;
}

/**
 * @brief Set removexattr route handle 
 * @return 0
 */
int UG_state_set_removexattr_rh( struct UG_state* state, int rh ) {
   state->removexattr_rh = rh;
   return 0;
}
