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

if [ "${RTPP_TEST_PREBUILT}" = "yes" ]
then
  # The CI image already contains every test binary. Its object files and
  # static archives are omitted, so do not recurse through the build targets.
  TEST_WITNESS_ENABLE=yes make -C tests check-TESTS
else
  TEST_WITNESS_ENABLE=yes make check
fi
