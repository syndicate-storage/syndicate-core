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

#include <libsyndicate/proc.h>

#include "core.h"
#include "driver.h"

// convert a URL into a CDN-ified URL 
// return 0 on success, and fill in *chunk with the URL 
// return -ENOMEM on OOM 
// return -EIO if the driver did not fulfill the request (driver error)
// return -EAGAIN if there are no free driver processes
// NOTE: this method is called by the Syndicate "impl_connect_cache" callback implementation in the UG.
int UG_driver_cdn_url( struct UG_state* core, char const* in_url, char** out_url ) {

   int rc = 0;
   struct SG_proc_group* group = NULL;
   struct SG_proc* proc = NULL;
   struct SG_driver* driver = NULL;
   struct SG_chunk in_url_chunk;
   struct SG_chunk out_url_chunk;

   SG_chunk_init( &in_url_chunk, (char*)in_url, strlen(in_url) );
   memset( &out_url_chunk, 0, sizeof(struct SG_chunk) );

   UG_state_rlock( core );

   // find a free cdn-url worker 
   driver = UG_state_driver( core );
   group = SG_driver_get_proc_group( driver, "cdn_url" );

   if( group != NULL && SG_proc_group_size( group ) > 0 ) {

      // get a free process 
      proc = SG_proc_group_acquire( group );
      if( proc == NULL ) {

         // got nothing 
         rc = -EAGAIN;
         goto UG_driver_cdn_url_finish;
      }

      // feed in the URL
      rc = SG_proc_write_chunk( SG_proc_stdin( proc ), &in_url_chunk );
      if( rc < 0 ) {
         
         SG_error("SG_proc_write_chunk(%d) rc = %d\n", SG_proc_stdin(proc), rc );
         
         rc = -EIO;
         goto UG_driver_cdn_url_finish;
      }

      // read back CDN-ified url 
      rc = SG_proc_read_chunk( SG_proc_stdout_f( proc ), &out_url_chunk );
      if( rc < 0 ) {

         SG_error("SG_proc_read_chunk(%d) rc = %d\n", fileno( SG_proc_stdout_f( proc ) ), rc );

         rc = -EIO;
         goto UG_driver_cdn_url_finish;
      }

      // success!
      *out_url = out_url_chunk.data;
      memset( &out_url_chunk, 0, sizeof(struct SG_chunk) );
   }
   else {

      // no-op driver 
      *out_url = SG_strdup_or_null( in_url );
      if( *out_url == NULL ) {
         rc = -ENOMEM;
      }
   }

UG_driver_cdn_url_finish:

   if( group != NULL && proc != NULL ) {
      SG_proc_group_release( group, proc );
   }
   
   UG_state_unlock( core );
   return rc;
}


// gateway callback to deserialize a chunk
// return 0 on success, and fill in *chunk
// return -ENOMEM on OOM 
// return -EIO if the driver did not fulfill the request (driver error)
// return -EAGAIN if we couldn't request the data, for whatever reason (i.e. no free processes)
int UG_driver_chunk_deserialize( struct SG_gateway* gateway, struct SG_request_data* reqdat, struct SG_chunk* in_chunk, struct SG_chunk* out_chunk, void* cls ) {
   
   int rc = 0;
   int64_t worker_rc = 0;
   struct UG_state* core = (struct UG_state*)SG_gateway_cls( gateway );
   struct SG_proc_group* group = NULL;
   struct SG_proc* proc = NULL;
   SG_messages::DriverRequest driver_req;
   struct SG_driver* driver = NULL;
   struct ms_client* ms = SG_gateway_ms( gateway );
   bool out_chunk_alloced = (out_chunk->data == NULL);  // will allocate
  
   UG_state_rlock( core );
   
   // find a free deserializer
   driver = UG_state_driver( core );
   group = SG_driver_get_proc_group( driver, "deserialize" );
   
   if( group != NULL && SG_proc_group_size( group ) > 0 ) {

      // get a free process
      proc = SG_proc_group_acquire( group );
      if( proc == NULL ) {
      
         // nothing running
         rc = -EAGAIN;
         goto UG_driver_chunk_deserialize_finish;
      }
      
      // feed in the metadata for this block
      rc = SG_proc_request_init( ms, reqdat, &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_request_init rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_chunk_deserialize_finish;
      }

      rc = SG_proc_write_request( SG_proc_stdin( proc ), &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_write_request rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_chunk_deserialize_finish;
      }

      // feed in the block itself 
      rc = SG_proc_write_chunk( SG_proc_stdin( proc ), in_chunk );
      if( rc < 0 ) {

         SG_error("SG_proc_write_chunk(%d) rc = %d\n", SG_proc_stdin(proc), rc );

         rc = -EIO;
         goto UG_driver_chunk_deserialize_finish;
      }

      // get error code 
      rc = SG_proc_read_int64( SG_proc_stdout_f( proc ), &worker_rc );
      if( rc < 0 ) {
         
         SG_error("SG_proc_read_int64('ERROR') rc = %d\n", rc );
         rc = -EIO;
         
         goto UG_driver_chunk_deserialize_finish;
      }
      
      // bail if the driver had a problem
      if( worker_rc != 0 ) {
         
         SG_error("Worker %d: deserialize rc = %d\n", SG_proc_pid( proc ), (int)worker_rc );
         rc = -EIO;
         
         goto UG_driver_chunk_deserialize_finish;
      }
      
      // get the serialized chunk 
      rc = SG_proc_read_chunk( SG_proc_stdout_f( proc ), out_chunk );
      if( rc < 0 ) {
         
         SG_error("SG_proc_read_chunk(%d) rc = %d\n", fileno( SG_proc_stdout_f(proc) ), rc );
         
         // OOM, EOF, or driver crash (rc is -ENOMEM, -ENODATA, or -EIO, respectively)
         goto UG_driver_chunk_deserialize_finish;
      }
   }
   else {
      
      // no-op deserializer
      rc = SG_chunk_copy_or_dup( out_chunk, in_chunk );
      if( rc != 0 ) {
         if( rc == -ERANGE ) {
            SG_error("Tried to copy buf len %" PRIu64 " to buf len %" PRIu64 "\n", in_chunk->len, out_chunk->len );
         }
      }
      
      ///////////////////////////////////////////////////// 
      char debug_buf[52];
      memset(debug_buf, 0, 52);
      for( unsigned int i = 0; i < (50 / 3) && i < out_chunk->len; i++ ) {
         char nbuf[5];
         memset(nbuf, 0, 5);
         snprintf(nbuf, 4, " %02X", out_chunk->data[i]);
         strcat(debug_buf, nbuf);
      }
      SG_debug("no-op deserializer (copied '%s...', %" PRIu64 " bytes total)\n", debug_buf, out_chunk->len);
      ///////////////////////////////////////////////////// 

   }
  
UG_driver_chunk_deserialize_finish: 

   if( group != NULL && proc != NULL ) {
      SG_proc_group_release( group, proc );
   }
   
   if( rc != 0 && out_chunk_alloced ) {
      SG_chunk_free( out_chunk );
   }

   UG_state_unlock( core );
   return rc;
}


// gateway callback to serialize a chunk
// return 0 on success 
// return -ENOMEM on OOM 
// return -EIO if we failed to communicate with the driver (i.e. driver error)
// return -EAGAIN if there were no free workers
int UG_driver_chunk_serialize( struct SG_gateway* gateway, struct SG_request_data* reqdat, struct SG_chunk* in_chunk, struct SG_chunk* out_chunk, void* cls ) {
   
   int rc = 0;
   int64_t worker_rc = 0;
   struct UG_state* core = (struct UG_state*)SG_gateway_cls( gateway );
   struct SG_proc_group* group = NULL;
   struct SG_proc* proc = NULL;
   struct SG_driver* driver = NULL;
   struct ms_client* ms = SG_gateway_ms( gateway );
   SG_messages::DriverRequest driver_req;
   
   UG_state_rlock( core );
   
   // find a worker 
   driver = UG_state_driver( core );
   group = SG_driver_get_proc_group( driver, "serialize" );
   
   if( group != NULL && SG_proc_group_size( group ) > 0 ) {
      
      // get a free worker 
      proc = SG_proc_group_acquire( group );
      if( proc == NULL ) {
         
         // no free workers
         SG_error("%s", "No free 'write' workers\n" );

         rc = -EAGAIN;
         goto UG_driver_chunk_serialize_finish;
      }

      // feed in the metadata for this block
      rc = SG_proc_request_init( ms, reqdat, &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_request_init rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_chunk_serialize_finish;
      }

      rc = SG_proc_write_request( SG_proc_stdin( proc ), &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_write_request rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_chunk_serialize_finish;
      }

      // put the block 
      rc = SG_proc_write_chunk( SG_proc_stdin( proc ), in_chunk );
      if( rc < 0 ) {
       
         SG_error("SG_proc_write_chunk(%d) rc = %d\n", SG_proc_stdin( proc ), rc );
         
         rc = -EIO;
         goto UG_driver_chunk_serialize_finish;
      }
      
      // get the reply 
      rc = SG_proc_read_int64( SG_proc_stdout_f( proc ), &worker_rc );
      if( rc < 0 ) {
         
         SG_error("SG_proc_read_int64(%d) rc = %d\n", fileno(SG_proc_stdout_f( proc )), rc );
         
         rc = -EIO;
         goto UG_driver_chunk_serialize_finish;
      }
      
      if( worker_rc < 0 ) {
         
         SG_error("Worker %d: serialize rc = %d\n", SG_proc_pid( proc ), (int)worker_rc );
         rc = -EIO;
         
         goto UG_driver_chunk_serialize_finish;
      }

      // get the deserialized chunk 
      rc = SG_proc_read_chunk( SG_proc_stdout_f( proc ), out_chunk );
      if( rc != 0 ) {

         SG_error("SG_proc_read_chunk(%d) rc = %d\n", fileno(SG_proc_stdout_f(proc)), rc );
         goto UG_driver_chunk_serialize_finish;
      }
   }
   else {
   
      // no-op serializer
      rc = SG_chunk_copy_or_dup( out_chunk, in_chunk );   
   }
   
UG_driver_chunk_serialize_finish:
   
   if( group != NULL && proc != NULL ) {
      SG_proc_group_release( group, proc );
   }
   
   UG_state_unlock( core );
   return rc;
}


// begin a get_chunk request.
// pass back the process handle
// return 0 on success, and set *proc_h
// return -EINVAL if there is not a `get_proc` driver implementation
// return -EIO on driver error
// return -EAGAIN if there are no free workers
int UG_driver_get_chunk_begin( struct SG_gateway* gateway, struct SG_request_data* reqdat, char const* RG_url, struct SG_proc** proc_h ) {

   int rc = 0;
   struct UG_state* core = (struct UG_state*)SG_gateway_cls( gateway );
   struct SG_proc_group* group = NULL;
   struct SG_proc* proc = NULL;
   struct SG_driver* driver = NULL;
   struct ms_client* ms = SG_gateway_ms( gateway );
   struct SG_chunk url_chunk;
   SG_messages::DriverRequest driver_req;

   SG_chunk_init( &url_chunk, (char*)RG_url, strlen(RG_url) );
   
   UG_state_rlock( core );
   
   // find a worker 
   driver = UG_state_driver( core );
   group = SG_driver_get_proc_group( driver, "get_chunk" );

   if( group != NULL && SG_proc_group_size( group ) > 0 ) {
      
      // get a free worker 
      proc = SG_proc_group_acquire( group );
      if( proc == NULL ) {
         
         // no free workers
         SG_error("%s", "No free 'write' workers\n" );

         rc = -EAGAIN;
         goto UG_driver_get_chunk_begin_finish;
      }

      // feed in the metadata for this block
      rc = SG_proc_request_init( ms, reqdat, &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_request_init rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_get_chunk_begin_finish;
      }

      // RG_url
      rc = SG_proc_write_chunk( SG_proc_stdin( proc ), &url_chunk );
      if( rc != 0 ) {

         SG_error("SG_proc_write_chunk rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_get_chunk_begin_finish;
      }

      // driver request
      rc = SG_proc_write_request( SG_proc_stdin( proc ), &driver_req );
      if( rc != 0 ) {

         SG_error("SG_proc_write_request rc = %d\n", rc );
         rc = -EIO;
         goto UG_driver_get_chunk_begin_finish;
      }

      // success!
      *proc_h = proc;
   }
   else {
      
      // no such group of workers 
      SG_error("%s", "No 'get_chunk' workers\n");
      rc = -EINVAL;
   }

UG_driver_get_chunk_begin_finish:

   UG_state_unlock( core );
   return rc;
}


// finish fetching a chunk from an RG
// return 0 on success and populate *chunk
// return -EIO on failure to communicate with the driver
// return -ENOENT if the worker had a problem
// return -ENOMEM on OOM
int UG_driver_get_chunk_end( struct SG_gateway* gateway, struct SG_proc* proc_h, struct SG_chunk* chunk ) {

   int rc = 0;
   int64_t worker_rc = 0;

   // get error code 
   rc = SG_proc_read_int64( SG_proc_stdout_f( proc_h ), &worker_rc );
   if( rc < 0 ) {
      
      SG_error("SG_proc_read_int64('ERROR') rc = %d\n", rc );
      rc = -EIO;
      
      goto UG_driver_get_chunk_end_finish;
   }
   
   // bail if the gateway worker had a problem
   if( worker_rc < 0 ) {
     
      SG_error("Request to worker %d failed, rc = %d\n", SG_proc_pid( proc_h ), (int)worker_rc );

      if( worker_rc == -ENOENT ) { 
          rc = -ENOENT;
      }
      else {
          rc = -EIO;
      }

      goto UG_driver_get_chunk_end_finish;
   }
   
   // get the (deserialized) block 
   rc = SG_proc_read_chunk_bound( SG_proc_stdout_f( proc_h ), chunk, chunk->len );
   if( rc < 0 ) {
      
      SG_error("SG_proc_read_chunk(%d) rc = %d\n", fileno( SG_proc_stdout_f(proc_h) ), rc );
      
      // OOM, EOF, or driver crash (rc is -ENOMEM, -ENODATA, or -EIO, respectively)
      goto UG_driver_get_chunk_end_finish;
   }

UG_driver_get_chunk_end_finish:
   return rc;
}

