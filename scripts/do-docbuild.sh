#!/bin/sh

set -e

BASEDIR="`dirname "${0}"`/.."
. "${BASEDIR}/scripts/build.conf.sub"
. "${BASEDIR}/scripts/functions.sub"

${APT_GET} install -y xsltproc fop tidy docbook-xml

./configure
make -C doc clean all
