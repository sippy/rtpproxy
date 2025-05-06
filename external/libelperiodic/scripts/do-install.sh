#!/bin/sh

set -e

PKGS="python3 python3-pip"

. $(dirname $0)/build.conf.sub

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
        ${PRE_INSTALL_CMD}
fi

${SUDO} apt-get update -y
${SUDO} apt-get -y install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
        ${POST_INSTALL_CMD}
fi
