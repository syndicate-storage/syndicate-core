#!/bin/bash

source subr.sh

CONFIG_DIR="$(setup)"
CONFIG_PATH="$CONFIG_DIR/syndicate.conf"
RANDOM_PATH="$(mktemp "/tmp/testvolume-XXXXXX")"
rm "$RANDOM_PATH"

echo "config dir: $CONFIG_DIR"

RANDOM_VOLUME_NAME="$(basename "$RANDOM_PATH")"

$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="$RANDOM_VOLUME_NAME" description="test create_volume" blocksize=4096 email="$SYNDICATE_ADMIN"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Failed to create volume"
fi

# should fail (duplicate) 
$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="$RANDOM_VOLUME_NAME" description="test create_volume duplicate" blocksize=4096 email="$SYNDICATE_ADMIN"
RC=$?

if [ $RC -eq 0 ]; then 
   test_fail "Created duplicate volume"
fi

# should fail (invalid name)
$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="" description="blank volume name" blocksize=4096 email="$SYNDICATE_ADMIN"
RC=$?

if [ $RC -eq 0 ]; then 
   test_fail "Created volume with empty name"
fi

# should fail (user does not exist)
$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="$RANDOM_VOLUME_NAME-2" description="no user" blocksize=4096 email="none@gmail.com"
RC=$?

if [ $RC -eq 0 ]; then 
   test_fail "Created volume with no local user data"
fi

# should fail (no blocksize)
$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="$RANDOM_VOLUME_NAME-4" description="no block size" email="$SYNDICATE_ADMIN"
RC=$?

if [ $RC -eq 0 ]; then 
   test_fail "Created volume with no blocksize"
fi

# cleanup 
# save the cert info...
SAVE_DIR="$(mktemp -d)"
pushd "$SAVE_DIR"
cp "$CONFIG_DIR/volumes/"* .
popd

$SYNDICATE_TOOL -c "$CONFIG_PATH" delete_volume "$RANDOM_VOLUME_NAME"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Failed to clean up volume $RANDOM_VOLUME_NAME"
fi

# is it gone?
VOLUME_JSON="$($SYNDICATE_TOOL -c "$CONFIG_PATH" list_volumes)"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Failed to list volumes"
fi

if [ -n "$(echo "$VOLUME_JSON" | grep "$RANDOM_VOLUME_NAME")" ]; then 
   test_fail "Failed to actually delete volume"
fi

# we expect the $VOLUME_ID.bundle.version to still be around 
if [ "$(ls -l "$CONFIG_DIR/volumes/" | wc -l)" != "2" ]; then 
   test_fail "volume config dir $CONFIG_DIR/volumes has the wrong number of files"
fi

# should fail--need the key
$SYNDICATE_TOOL -c "$CONFIG_PATH" delete_volume "$RANDOM_VOLUME_NAME"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Delete should succeed even when we don't have the key"
fi

# try again, with keys
# should succeed on the MS 
cp "$SAVE_DIR/"* "$CONFIG_DIR/volumes"
rm -rf "$SAVE_DIR"

$SYNDICATE_TOOL -c "$CONFIG_PATH" delete_volume "$RANDOM_VOLUME_NAME"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Delete should be idempotent on the MS"
fi

test_success
exit 0
