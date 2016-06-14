#!/bin/bash

set -u

SYNDICATE_TOOL=${SYNDICATE_TOOL:-./build_root/bin/syndicate}
SYNDICATE_ADMIN=${SYNDICATE_ADMIN:-jcnelson@cs.princeton.edu}
SYNDICATE_MS=${SYNDICATE_MS:-"http://localhost:8080"}
SYNDICATE_PRIVKEY_PATH=${SYNDICATE_PRIVKEY_PATH:-./ms_src/admin.pem}
SYNDICATE_CONFIG=

TESTLOGS="/tmp/syndicate-test-logs"
mkdir -p "$TESTLOGS"

TESTNAME="$(basename "$0" | sed 's/\.sh$//g')"
TESTLOG="$TESTLOGS/$TESTNAME.log"

# Check for presence of syndicate binary
if ! [ -f "$SYNDICATE_TOOL" ]; then
   echo >&2 "No such file or directory: $SYNDICATE_TOOL"
   exit 1
fi

make_tmp_config_dir() {
   mktemp -d "/tmp/syndicate-test-config.XXXXXX"
}

setup() {
   # does Syndicate's setup with the admin
   # $1: config dir (optional)
   # prints out config dir

   local CONFIG_DIR
   CONFIG_DIR=

   if [ $# -gt 0 ]; then
       CONFIG_DIR="$1"
    fi

   if [ -z "$CONFIG_DIR" ]; then
      CONFIG_DIR="$(make_tmp_config_dir)"
   fi

   $SYNDICATE_TOOL --trust_public_key -c "$CONFIG_DIR/syndicate.conf" --debug setup "$SYNDICATE_ADMIN" "$SYNDICATE_PRIVKEY_PATH" "$SYNDICATE_MS"
   RC=$?

   if [ $RC -ne 0 ]; then
       test_fail "Failed to set up in $CONFIG_DIR"
   else
       SYNDICATE_CONFIG="$CONFIG_DIR"
       echo "$CONFIG_DIR"
   fi

   return 0
}

test_success() {
   # clean up
   if [ -n "$SYNDICATE_CONFIG" ] && [ -n "$(echo "$SYNDICATE_CONFIG" | egrep "^/tmp/")" ]; then
      echo "rm -rf "$SYNDICATE_CONFIG""
   fi

   echo "TEST SUCCESS: $TESTNAME"
   exit 0
}

test_fail() {
   echo "TEST FAILURE: $TESTNAME $@"
   exit 1
}
