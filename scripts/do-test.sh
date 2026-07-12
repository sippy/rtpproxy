#!/bin/sh

set -e

MYUID=`id -u`

if [ ${MYUID} -eq 0 ]
then
  chown -R nobody .
fi

TEST_WITNESS_ENABLE=yes make check || (cat tests/test-suite.log; exit 1)
