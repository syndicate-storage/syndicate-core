#!/bin/sh

ROOTDIR="$(pwd)"
TESTOUT="$(mktemp -d /tmp/syndicate-tap-XXXXXX)"

source ./subr-ms.sh

# run tests and output in TAP format
DIRS=
while IFS= read TESTDIR; do
    if [ "$TESTDIR" = "." ] || [ "$TESTDIR" = ".." ]; then 
       continue
    fi

    if [ -d "$TESTDIR" ]; then
        DIRS="$DIRS $TESTDIR"
    fi
done <<EOF
$(ls "$ROOTDIR")
EOF

# get test count
TESTCOUNT=1
for TESTDIR in $DIRS; do
   TESTS=
   while IFS= read TESTNAME; do
      if [ -f "$TESTDIR/$TESTNAME" ] && [ -x "$TESTDIR/$TESTNAME" ] && ! [ -L "$TESTDIR/$TESTNAME" ]; then 
         TESTCOUNT=$(($TESTCOUNT+1))
      fi
   done <<EOF
$(ls "$TESTDIR")
EOF
done

# start MS 
MS_PID="$(ms_dev_start)"
if [ $? -ne 0 ]; then 
   echo >&2 "Failed to start MS"
   exit 1
fi

# begin run 
echo "1..$TESTCOUNT"
TESTIDX=1
   
for TESTDIR in $DIRS; do
   while IFS= read TESTNAME; do
      if [ -f "$TESTDIR/$TESTNAME" ] && [ -x "$TESTDIR/$TESTNAME" ] && ! [ -L "$TESTDIR/$TESTNAME" ]; then 
         # run test
         cd "$TESTDIR"
         "./$TESTNAME" > "$TESTOUT/$TESTNAME.out" 2>&1
         RC=$?
         cd ..

         # log test result
         if [ $RC -eq 0 ]; then 
            echo "ok $TESTIDX - $TESTNAME"
         else
            echo "not ok $TESTIDX - $TESTNAME"
         fi

         # diagnostics
         cat "$TESTOUT/$TESTNAME.out" | sed 's/^\(.*\)$/# \1/g'

         # next test 
         TESTIDX=$(($TESTIDX + 1))
      fi
   done <<EOF
$(ls "$TESTDIR")
EOF
done

# stop the MS 
ms_dev_stop "$MS_PID"
if [ $? -ne 0 ]; then 
   echo >&2 "Failed to stop MS"
   exit 1
fi

exit 0 
