#!/bin/sh

set -e
set -x

MYPATH="`realpath "${0}"`"
RTPDIR="`dirname "${MYPATH}"`/.."

apt-get -y update -qq

. "docker/clang_ver.sub"
set_clang_env
${APT_INSTALL} ca-certificates
install_clang

${APT_INSTALL} ${LIB_DEPS} ${BUILD_DEPS}
