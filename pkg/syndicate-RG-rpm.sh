#!/bin/bash

if ! [ $1 ]; then
   echo "Usage: $0 PACKAGE_ROOT"
   exit 1
fi

ROOT=$1
NAME="syndicate-rg"
VERSION="0.$(date +%Y\%m\%d\%H\%M\%S)"

DEPS="python-syndicate" 

DEPARGS=""
for pkg in $DEPS; do
   DEPARGS="$DEPARGS -d $pkg"
done

source /usr/local/rvm/scripts/rvm

rm -f $NAME-0*.rpm

fpm --force -s dir -t rpm -a noarch -v $VERSION -n $NAME $DEPARGS -C $ROOT --license "Apache 2.0" --vendor "Princeton University" --maintainer "Jude Nelson <jcnelson@cs.princeton.edu>" --url "https://github.com/jcnelson/syndicate" --description "Syndicate Replica Gateway." $(ls $ROOT)

