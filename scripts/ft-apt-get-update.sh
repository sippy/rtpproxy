#!/bin/sh

set -e
set -x

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get update -y --fix-missing
${SUDO} apt-get upgrade -y
