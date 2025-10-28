#!/bin/sh

set -e
set -x

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get update -y --fix-missing

if test -f /etc/apt/sources.list && grep -q bionic /etc/apt/sources.list
then
  ${SUDO} apt-get install -y ca-certificates
  ${SUDO} perl -pi -e 's|http://|https://|g' /etc/apt/sources.list
  ${SUDO} apt-get update -y --fix-missing
fi

${SUDO} apt-mark hold grub-efi-amd64-signed
${SUDO} apt-get autoclean
