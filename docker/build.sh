#!/bin/sh

set -e
set -x

MYPATH="`realpath "${0}"`"
RTPDIR="`dirname "${MYPATH}"`/.."

CONFIGURE_ARGS="--enable-librtpproxy"
ARCH="`dpkg --print-architecture`"

if [ "${ARCH}" != "armhf" ]
then
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-lto"
fi

cd "${RTPDIR}"

_CCACHE_ROOT="${CCACHE_ROOT:-"${RTPDIR}/ccache"}"
CCACHE_ROOT="`realpath "${_CCACHE_ROOT}"`"
export PATH="/usr/lib/ccache:${PATH}"
export CCACHE_DIR="${CCACHE_ROOT}/${ARCH}"
if [ ! -e "${CCACHE_DIR}" ]
then
  mkdir -p "${CCACHE_DIR}"
fi
for dir in ${CCACHE_ROOT}/*
do
  if [ "${dir}" = "${CCACHE_DIR}" ]
  then
    continue
  fi
  rm -rf "${dir}"
done

ccache --max-size=20M
ccache --set-config=sloppiness=file_macro
ccache --cleanup
ccache --zero-stats

. "docker/clang_ver.sub"

CC=clang-${CLANG_VER} AR=llvm-ar-${CLANG_VER} RANLIB=llvm-ranlib-${CLANG_VER} \
 NM=llvm-nm-${CLANG_VER} STRIP=llvm-strip-${CLANG_VER} CFLAGS="-O3 -pipe" \
 ./configure ${CONFIGURE_ARGS}
make -j8 all
make install

ccache --show-stats

apt-get -y remove --purge ${BUILD_DEPS}
apt-get -y autoremove --purge

find / -xdev -xtype l
find / -xdev -xtype l -delete
