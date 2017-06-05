#!/bin/bash

ADMIN_USER="jcnelson@cs.princeton.edu"

syndicate list_gateways > /tmp/gateways.json || exit 1
syndicate list_users > /tmp/users.json || exit 1
syndicate list_volumes > /tmp/volumes.json || exit 1

for gateway_name in $(cat /tmp/gateways.json | jq '.[].name' | sed -r 's/"//g'); do
   echo "delete gateway '$gateway_name'..."
done

for volume_name in $(cat /tmp/volumes.json | jq '.[].name' | sed -r 's/"//g'); do
   echo "delete volume '$volume_name'..."
done

for user_name in $(cat /tmp/users.json | jq '.[].email' | sed -r 's/"//g'); do
   if [[ "$user_name" == "$ADMIN_USER" ]]; then 
      echo "skip admin user '$user_name'..."
      continue
   fi

   echo "delete user '$user_name'..."
done

exit 0

