#!/bin/sh

set -e
set -x

MYPATH="`realpath "${0}"`"
RTPDIR="`dirname "${MYPATH}"`/.."

apt-get -y update -qq

. "docker/clang_ver.sub"

if [ ${CLANG_VER} -gt 16 ]
then
  ${APT_INSTALL} curl gpg ca-certificates
  echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${CLANG_VER} main" > /etc/apt/sources.list.d/llvm.list
  curl https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor > /usr/share/keyrings/llvm.gpg
  apt-get -y update -qq
fi

${APT_INSTALL} ${LIB_DEPS} ${BUILD_DEPS}
