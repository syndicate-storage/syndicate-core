#!/bin/sh

if [ -z "$MS_SRC_ROOT" ]; then 
    MS_SRC_ROOT=/usr/local/src/syndicate/ms
fi

# start up the development MS
# return 0 on success, and echo the MS PID
# return 1 on failure
ms_dev_start() {
   which dev_appserver.py >/dev/null
   if [ $? -ne 0 ]; then 
       echo >&2 "dev_appserver.py is not installed"
       return 1
   fi

   # make admin key 
   
   dev_appserver.py --clear_datastore=True "$MS_SRC_ROOT" &
   echo "$!"
   return 0
}


# stop the MS
# $1 is the PID
# return 0 on success
# return 1 on failure
ms_dev_stop() {

   local MS_PID
   MS_PID="$1"

   if [ -z "$MS_PID" ]; then 
      return 1
   fi

   kill -s SIGTERM $MS_PID
   return $?
}
