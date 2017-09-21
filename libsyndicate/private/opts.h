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
 * @file libsyndicate/private/opts.h
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief Private header file for command-line options
 *
 * Kept private to prevent direct access to this structure
 * by files and programs that aren't part of libsyndicate.so.
 *
 * Parse, execute, and print common command-line options available to syndicate-core
 *
 * @see libsyndicate/opts.cpp
 */

#ifndef _SYNDICATE_OPTS_PRIVATE_H_
#define _SYNDICATE_OPTS_PRIVATE_H_

#include "libsyndicate/libsyndicate.h"
#include "libsyndicate/storage.h"

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 
#endif 

/// command-line options
struct md_opts {
   char* config_file;           ///< The configuration file
   char* username;              ///< Username
   char* volume_name;           ///< Volume name
   char* ms_url;                ///< The MS url
   char* gateway_name;          ///< The gateway name
   int debug_level;             ///< Debug level
   bool foreground;             ///< Flag, running if foreground or background
   
   // not set by the parser 
   bool client;                 ///< Flag, is or is not client (not set by parser)
   bool ignore_driver;          ///< If true, no attempt to load the driver will be made (not set by parser)
   uint64_t gateway_type;       ///< The gateway type (not set by parser)

   char const* driver_exec_str; ///< Driver executable
   char const** driver_roles;   ///< Driver roles
   int num_instances;           ///< Number of driver instances
   size_t num_driver_roles;     ///< Number of driver roles
};

#endif
