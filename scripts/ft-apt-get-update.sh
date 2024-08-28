#!/bin/sh

set -e
set -x

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get update -y --fix-missing
${SUDO} apt-mark hold grub-efi-amd64-signed
${SUDO} apt-get autoclean
