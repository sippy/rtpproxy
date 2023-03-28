#!/bin/sh

set -e
set -x

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} gem install apt-spy2
${SUDO} apt-spy2 check --strict --country=US
${SUDO} apt-spy2 fix --commit --strict --country=US
