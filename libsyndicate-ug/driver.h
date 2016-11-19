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

#ifndef _UG_DRIVER_H_
#define _UG_DRIVER_H_

#include <libsyndicate/libsyndicate.h>
#include <libsyndicate/gateway.h>

struct UG_state;

extern "C" {

int UG_driver_cdn_url( struct UG_state* core, char const* in_url, char** out_url );
int UG_driver_chunk_deserialize( struct SG_gateway* gateway, struct SG_request_data* reqdat, struct SG_chunk* in_chunk, struct SG_chunk* out_chunk, void* cls );
int UG_driver_chunk_serialize( struct SG_gateway* gateway, struct SG_request_data* reqdat, struct SG_chunk* in_chunk, struct SG_chunk* out_chunk, void* cls );

// these don't plug into SG_gateway, but get called by read/write 

int UG_driver_get_chunk_begin( struct SG_gateway* gateway, struct SG_request_data* reqdat, char const* RG_url, struct SG_proc** proc_h );
int UG_driver_get_chunk_end( struct SG_gateway* gateway, struct SG_proc* proc_h, struct SG_chunk* out_chunk );

}

#endif
