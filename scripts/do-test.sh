#!/bin/sh

set -e

MYUID=`id -u`

if [ ${MYUID} -eq 0 ]
then
  groupadd --system rtpproxy
  useradd --system --gid rtpproxy --home-dir /var/lib/rtpproxy --no-create-home \
   --shell /usr/sbin/nologin rtpproxy
  chown -R rtpproxy .
fi

TEST_WITNESS_ENABLE=yes make check || (cat tests/test-suite.log; exit 1)
