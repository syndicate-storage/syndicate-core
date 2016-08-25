#!/bin/bash

source subr.sh

CONFIG_DIR="$(setup)"
CONFIG_PATH="$CONFIG_DIR/syndicate.conf"
RANDOM_PATH="$(mktemp "/tmp/testvolume-XXXXXX")"
rm "$RANDOM_PATH"

echo "config dir: $CONFIG_DIR"

RANDOM_VOLUME_NAME="$(basename "$RANDOM_PATH")"
RANDOM_USER_NAME="$(basename "$RANDOM_PATH")"@gmail.com

RANDOM_UG_GATEWAY_NAME="$(basename "$RANDOM_PATH")-UG"
RANDOM_RG_GATEWAY_NAME="$(basename "$RANDOM_PATH")-RG"
RANDOM_AG_GATEWAY_NAME="$(basename "$RANDOM_PATH")-AG"

$SYNDICATE_TOOL -c "$CONFIG_PATH" create_volume name="$RANDOM_VOLUME_NAME" description="test create_volume" blocksize=4096 email="$SYNDICATE_ADMIN"
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Failed to create volume"
fi

$SYNDICATE_TOOL -c "$CONFIG_PATH" create_user "$RANDOM_USER_NAME" auto max_volumes=20 max_gateways=21
RC=$?

if [ $RC -ne 0 ]; then 
   test_fail "Failed to create user"
fi

for NAME in $RANDOM_UG_GATEWAY_NAME $RANDOM_RG_GATEWAY_NAME $RANDOM_AG_GATEWAY_NAME; do

   GW_NAME="$NAME-01"
   GW_TYPE="$(echo "$NAME" | sed -r 's/(.*)-([URA]{1}G)$/\2/g')"

   # should succeed
   $SYNDICATE_TOOL -c "$CONFIG_PATH" create_gateway email="$SYNDICATE_ADMIN" volume="$RANDOM_VOLUME_NAME" name="$GW_NAME" private_key=auto type="$GW_TYPE"
   RC=$?

   if [ $RC -ne 0 ]; then 
      test_fail "Failed to create $GW_NAME"
   fi

   # should fail (duplicate)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" create_gateway email="$SYNDICATE_ADMIN" volume="$RANDOM_VOLUME_NAME" name="$GW_NAME" private_key=auto type="$GW_TYPE"
   RC=$?

   if [ $RC -eq 0 ]; then 
      test_fail "Created duplicate $GW_NAME"
   fi

   # should fail (invalid name)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" create_gateway email="$SYNDICATE_ADMIN" volume="$RANDOM_VOLUME_NAME" name="" private_key=auto type="$GW_TYPE"
   RC=$?

   if [ $RC -eq 0 ]; then 
      test_fail "Created nameless gateway"
   fi

   # should fail (user does not exist)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" create_gateway email="none@gmail.com" volume="$RANDOM_VOLUME_NAME" name="$NAME-02" private_key=auto type="$GW_TYPE"
   RC=$?

   if [ $RC -eq 0 ]; then 
      test_fail "Created gateway for nonexistant user"
   fi

   # should fail (volume does not exist)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" create_gateway email="$SYNDICATE_ADMIN" volume="$RANDOM_VOLUME_NAME-2" name="$GW_NAME" private_key=auto type="$GW_TYPE"
   RC=$?
   
   if [ $RC -eq 0 ]; then 
      test_fail "Created gateway for nonexistant volume"
   fi

   # should fail (user is not the volume owner)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" -u "$RANDOM_USER_NAME" create_gateway email="$RANDOM_USER_NAME" volume="$RANDOM_VOLUME_NAME" name="$GW_NAME" private_key=auto type="$GW_TYPE"
   RC=$?

   if [ $RC -eq 0 ]; then
      test_fail "Created gateway with unprivileged user"
   fi

done

# clean up 
SAVE_DIR="$(mktemp -d)"
pushd "$SAVE_DIR"
cp "$CONFIG_DIR/gateways/"* .
popd

for NAME in $RANDOM_UG_GATEWAY_NAME $RANDOM_AG_GATEWAY_NAME; do
   
   GW_NAME="$NAME-01"

   # should fail (not the volume owner)
   $SYNDICATE_TOOL -c "$CONFIG_PATH" -u "$RANDOM_USER_NAME" delete_gateway "$GW_NAME"
   RC=$?

   if [ $RC -eq 0 ]; then 
      test_fail "Deleted $GW_NAME with non-volume-owner user"
   fi

   # should succeed
   $SYNDICATE_TOOL -c "$CONFIG_PATH" delete_gateway "$GW_NAME"
   RC=$?

   if [ $RC -ne 0 ]; then 
      test_fail "Failed to delete $GW_NAME"
   fi

   # is it gone?
   GATEWAY_JSON="$($SYNDICATE_TOOL -c "$CONFIG_PATH" list_gateways)"
   RC=$?

   if [ $RC -ne 0 ]; then 
      test_fail "Failed to list gateways"
   fi

   if [ -n "$(echo "$GATEWAY_JSON" | grep "$GW_NAME")" ]; then 
      test_fail "Failed to actually delete gateway"
   fi
done

for NAME in $RANDOM_RG_GATEWAY_NAME; do 

   GW_NAME="$NAME-01"

   # should succeed, since we're the volume admin
   $SYNDICATE_TOOL -c "$CONFIG_PATH" delete_gateway "$GW_NAME"
   RC=$?

   if [ $RC -ne 0 ]; then 
      test_fail "Failed to deleted gateway $GW_NAME without the key"
   fi
done

# restore keys 
cp "$SAVE_DIR/"* "$CONFIG_DIR/gateways"
rm -rf "$SAVE_DIR"

for NAME in $RANDOM_UG_GATEWAY_NAME $RANDOM_RG_GATEWAY_NAME $RANDOM_AG_GATEWAY_NAME; do

   GW_NAME="$NAME-01"

   # should succeed
   $SYNDICATE_TOOL -c "$CONFIG_PATH" delete_gateway "$GW_NAME"
   RC=$?

   if [ $RC -ne 0 ]; then 
      test_fail "Delete $GW_NAME not idempotent"
   fi
done

test_success
exit 0

