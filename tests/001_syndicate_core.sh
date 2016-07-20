#!/usr/bin/env bash


SCRIPTDIR=`dirname $0` # find parent directory of this script
ROOTDIR=`readlink -f ${SCRIPTDIR}` # find the absolute path
TESTOUT="$(mktemp -d /tmp/syndicate-tap-XXXXXX)"
CONFIG_VARS="$1"

if [ -n "$CONFIG_VARS" ]; then
   source "$CONFIG_VARS"

   # make available to subprocesses
   while IFS= read ENVAR_STMT; do
      eval "export $ENVAR_STMT"
   done <<EOF
$(cat "$CONFIG_VARS")
EOF
fi

# local MS?
MS_PID=
if [ -z "$SYNDICATE_MS" ]; then
    source ${SCRIPTDIR}/subr-ms.sh

    # TODO: set up MS
    MS_PID="$(ms_dev_start)"
    if [ $? -ne 0 ]; then
       echo >&2 "Failed to start MS"
       exit 1
    fi
fi

# run tests and output in TAP format
DIRS=
while IFS= read TESTDIR; do
    if [ "$TESTDIR" = "." ] || [ "$TESTDIR" = ".." ]; then
       continue
    fi

    if [ -d "${ROOTDIR}/${TESTDIR}" ]; then
        DIRS="$DIRS ${ROOTDIR}/${TESTDIR}"
    fi
done <<EOF
$(ls "$ROOTDIR")
EOF

# get test count
TESTCOUNT=0
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

# begin run
echo "1..$TESTCOUNT"
TESTIDX=1

for TESTDIR in $DIRS; do
   while IFS= read TESTNAME; do
      if [ -f "$TESTDIR/$TESTNAME" ] && [ -x "$TESTDIR/$TESTNAME" ] && ! [ -L "$TESTDIR/$TESTNAME" ]; then

         # run test
         cd "$TESTDIR"
         # note, %N is a gnu extension for nanoseconds
         START_NS=$(date +%s%N)
         "./$TESTNAME" > "$TESTOUT/$TESTNAME.out" 2>&1
         RC=$?
         END_NS=$(date +%s%N)
         cd ..

         # log test result
         if [ $RC -eq 0 ]; then
            echo "ok $TESTIDX - $TESTNAME"
         else
            echo "not ok $TESTIDX - $TESTNAME"
         fi

         # timing info
         DURATION_MS=$(((${END_NS}-${START_NS})/1000000))
         echo "  ---"
         echo "    duration_ms: $DURATION_MS"
         echo "  ..."

         # diagnostics
         cat "$TESTOUT/$TESTNAME.out" | sed 's/^\(.*\)$/# \1/g'

         # next test
         TESTIDX=$(($TESTIDX + 1))
      fi
   done <<EOF
$(ls "$TESTDIR")
EOF
done

# stop the MS, if need be
if [ -n "$MS_PID" ]; then
   ms_dev_stop "$MS_PID"
   if [ $? -ne 0 ]; then
      echo >&2 "Failed to stop MS"
      exit 1
   fi
fi

exit 0
