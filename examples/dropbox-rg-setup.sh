#!/bin/sh
########################################

# tailor these variables to your needs
USERNAME="jcnelson@cs.princeton.edu"
VOLUME_NAME="testVolume"
RG_GATEWAY_NAME="dropboxRG"

# before running this script, the following preconditions must be met:
# * the user "$USERNAME" must be a valid Syndicate user.  You can create it with `syndicate create_user` using an admin account.
# * the volume "$VOLUME_NAME" must be an existing volume.  You can create it with `syndicate create_volume`.
# * the gateway "$RG_GATEWAY_NAME" must exist and be an RG.  You can create it with `syndicate create_gateway`.
########################################

# get dropbox API key from CLI
DROPBOX_API_KEY="$1"
test -n "$DROPBOX_API_KEY" || exit 1

# get path to driver 
DROPBOX_DRIVER_PATH="$(python -c 'import syndicate.rg.drivers.dropbox as dbx; print dbx.__path__[0]')"
test $? -eq 0 || exit 1

# set up an instance of the driver with our secrets
DRIVER_DIR="$(mktemp -d)"
echo "Writing configured driver to $DRIVER_DIR"

cp -a "$DROPBOX_DRIVER_PATH"/*.py "$DRIVER_DIR"

# make secrets
echo "{'DROPBOX_TOKEN': '$DROPBOX_API_KEY'}" > "$DRIVER_DIR"/secrets

# install the driver
echo "Installing driver..."
syndicate -d update_gateway "$RG_GATEWAY_NAME" driver="$DRIVER_DIR"

# clean up
echo "Cleaning up..."
rm -rf "$DRIVER_DIR"
