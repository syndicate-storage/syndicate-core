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
 * @file libsyndicate/opts.h
 * @author Jude Nelson
 * @date 9 Mar 2016
 *
 * @brief Header file for command-line options
 *
 * Parse, execute, and print common command-line options available to syndicate-core
 *
 * @see libsyndicate/opts.cpp
 */

#ifndef _SYNDICATE_OPTS_H_
#define _SYNDICATE_OPTS_H_

#include "libsyndicate/libsyndicate.h"
#include "libsyndicate/storage.h"

#include <getopt.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 
#endif 

struct md_opts;

extern "C" {

/**
 * @brief Parse args for common tool options
 *
 * @param[in] count Number of md_opts structs
 * @return Ptr to md_opts array
 */
struct md_opts* md_opts_new( int count );

/**
 * @brief Populate md_opts struct with default values
 *
 * @param[in] opts The md_opts array
 * @return 0
 */
int md_opts_default( struct md_opts* opts );

/**
 * @brief Parse opts from argv
 *
 * @param[in] opts The md_opts array
 * @param[in] argc Number of arguments
 * @param[in] argv Arguments
 * @param[in] optind Ptr to null or index
 * @param[in] special_opts String of special options
 * @param[in] special_opt_handler Integer number of special options in *special_opts
 * @retval 0 on success
 * @retval 1 if caller wanted help
 * @retval -EINVAL On invalid duplicate short opt definitions
 * @retval -ENOMEM On out of memory
 */
int md_opts_parse( struct md_opts* opts, int argc, char** argv, int* optind, char const* special_opts, int (*special_opt_handler)(int, char*) );

/**
 * @brief Free the md_opts structure
 *
 * @param[in] opts The md_opts structure 
 * @return 0
 */
int md_opts_free( struct md_opts* opts );

/**
 * @brief Print the common command-line options available.
 *
 * @return 0
 */
void md_common_usage(void);

/**
 * @brief Parse a long
 *
 * @retval 0 Success
 * @retval -1 Failed
 */
int md_opts_parse_long( int c, char* opt, long* result );

// getters

/**
 * @brief Get the client
 *
 * @param[in] opts The md_opts structure 
 * @return client
 */
bool md_opts_get_client( struct md_opts* opts );

/**
 * @brief Get the ignore-driver disposition
 *
 * @param[in] opts The md_opts structure 
 * @return ignore_driver
 */
bool md_opts_get_ignore_driver( struct md_opts* opts );

/**
 * @brief Get the gateway_type
 *
 * @param[in] opts The md_opts structure 
 * @return gateway_type
 */
uint64_t md_opts_get_gateway_type( struct md_opts* opts );

/**
 * @brief Get the config_file
 *
 * @param[in] opts The md_opts structure 
 * @return config_file string
 */
char const* md_opts_get_config_file( struct md_opts* opts );

// setters (e.g. for python)
/**
 * @brief Set the client
 *
 * @param[in] opts The md_opts structure 
 * @param[in] client Client value
 */
void md_opts_set_client( struct md_opts* opts, bool client );

/**
 * @brief Set the ignore_driver
 *
 * @param[in] opts The md_opts structure 
 * @param[in] ignore_driver Set to ignore driver
 */
void md_opts_set_ignore_driver( struct md_opts* opts, bool ignore_driver );

/**
 * @brief Set the gateway type
 *
 * @param[in] opts The md_opts structure 
 * @param[in] type The gateway type
 */
void md_opts_set_gateway_type( struct md_opts* opts, uint64_t type );

/**
 * @brief Set the config_filepath
 *
 * @param[in] opts The md_opts structure 
 * @param[in] config_filepath Configuration filepath
 */
void md_opts_set_config_file( struct md_opts* opts, char* config_filepath );

/**
 * @brief Set the username
 *
 * @param[in] opts The md_opts structure 
 * @param[in] username The username
 */
void md_opts_set_username( struct md_opts* opts, char* username );

/**
 * @brief Set the volume name
 *
 * @param[in] opts The md_opts structure 
 * @param[in] volume_name The volume name
 */
void md_opts_set_volume_name( struct md_opts* opts, char* volume_name );

/**
 * @brief Set the gateway name
 *
 * @param[in] opts The md_opts structure 
 * @param[in] gateway_name The gateway name
 */
void md_opts_set_gateway_name( struct md_opts* opts, char* gateway_name );

/**
 * @brief Set the URL to the MS
 *
 * @param[in] opts The md_opts structure 
 * @param[in] ms_url URL to the MS
 */
void md_opts_set_ms_url( struct md_opts* opts, char* ms_url );

/**
 * @brief Set to run in foreground
 *
 * @param[in] opts The md_opts structure 
 * @param[in] foreground Run in foreground
 */
void md_opts_set_foreground( struct md_opts* opts, bool foreground );

/**
 * @brief Set the driver options
 *
 * @param[in] opts The md_opts structure 
 * @param[in] driver_exec_str The exec string
 * @param[in] driver_roles Driver roles
 * @param[in] driver_instances Driver instance
 * @param[in] num_driver_roles Number of roles
 */
void md_opts_set_driver_config( struct md_opts* opts, char const* driver_exec_str, char const** driver_roles, int driver_instances, size_t num_driver_roles );

}

#endif
