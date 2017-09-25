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
 * @file libsyndicate/ms/cert.h
 * @author Jude Nelson
 * @date Mar 9 2016
 *
 * @brief Header file for cert.cpp
 *
 * @see libsyndicate/ms/cert.cpp
 */

#ifndef _MS_CLIENT_CERT_H_
#define _MS_CLIENT_CERT_H_

#include "libsyndicate/libsyndicate.h"

// prototypes 
struct ms_volume;

/// Structure for holding gateway information and driver data
struct ms_gateway_cert {
   uint64_t user_id;            ///< Syndicate User ID
   uint64_t gateway_id;         ///< Gateway ID
   uint64_t gateway_type;       ///< What kind of gateway
   uint64_t volume_id;          ///< Volume ID
   
   char* name;                  ///< Gateway name
   char* hostname;              ///< What host this gateway runs on
   int portnum;                 ///< What port this gateway listens on
   
   char* driver_text;           ///< Driver information (only retained for our gateway).  Fetched separately from the cert.
   uint64_t driver_text_len;    ///< Length of the above
   
   unsigned char* driver_hash;  ///< sha256 of the driver information.
   size_t driver_hash_len;      ///< Length of the above 
   
   EVP_PKEY* pubkey;            ///< Gateway public key
   
   uint64_t caps;               ///< Gateway capabilities
   uint64_t expires;            ///< When this certificate expires
   uint64_t version;            ///< Version of this certificate (increases monotonically)
   
   ms::ms_gateway_cert* pb;     ///< Protobuf'ed cert we got
   ms::ms_user_cert* user_pb;   ///< Protobuf'ed user cert that owns this gateway
};

extern "C" {

// init/free
int ms_client_gateway_cert_init( struct ms_gateway_cert* cert, uint64_t my_gateway_id, ms::ms_gateway_cert* ms_cert );
void ms_client_gateway_cert_free( struct ms_gateway_cert* cert );
void ms_client_cert_bundle_free( ms_cert_bundle* bundle );

// getters TODO
uint64_t ms_client_gateway_cert_version( struct ms_gateway_cert* cert );
ms::ms_user_cert* ms_client_gateway_cert_user( struct ms_gateway_cert* cert );
ms::ms_gateway_cert* ms_client_gateway_cert_gateway( struct ms_gateway_cert* cert );
char const* ms_client_gateway_cert_name( struct ms_gateway_cert* cert );
EVP_PKEY* ms_client_gateway_pubkey( struct ms_gateway_cert* cert );
int ms_client_gateway_driver_hash_buf( struct ms_gateway_cert* cert, unsigned char* hash );
char const* ms_client_gateway_cert_hostname( struct ms_gateway_cert* cert );
int ms_client_gateway_cert_portnum( struct ms_gateway_cert* cert );

uint64_t ms_client_gateway_cert_user_id( struct ms_gateway_cert* cert );
uint64_t ms_client_gateway_cert_gateway_type( struct ms_gateway_cert* cert );
uint64_t ms_client_gateway_cert_gateway_id( struct ms_gateway_cert* cert );
uint64_t ms_client_gateway_cert_volume_id( struct ms_gateway_cert* cert );

// setters 
int ms_client_gateway_cert_set_user( struct ms_gateway_cert* cert, ms::ms_user_cert* user_pb );
int ms_client_gateway_cert_set_driver( struct ms_gateway_cert* cert, char* driver_text, uint64_t driver_text_len );

// validation
int ms_client_cert_has_public_key( ms::ms_gateway_cert* ms_cert );

// setters 
int ms_client_cert_bundle_put( ms_cert_bundle* bundle, struct ms_gateway_cert* cert );

}
#endif
