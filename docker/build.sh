#!/bin/sh

set -e
set -x

MYPATH="`realpath "${0}"`"
RTPDIR="`dirname "${MYPATH}"`/.."

LIB_DEPS="libsrtp2-1 libbcg729-0 libgsm1 libsndfile1 libunwind8 libssl3"

BUILD_DEPS="file pkg-config clang-15 ccache git make \
 libsrtp2-dev libbcg729-dev libgsm1-dev libsndfile1-dev \
 libunwind-dev libssl-dev"

apt-get -y update -qq

apt-get -y install ${LIB_DEPS} ${BUILD_DEPS}

CONFIGURE_ARGS="--enable-librtpproxy"
ARCH="`dpkg --print-architecture`"

if [ "${ARCH}" != "armhf" ]
then
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-lto"
fi

cd "${RTPDIR}"

CCACHE_ROOT="${RTPDIR}/ccache"
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

CC=clang-15 AR=llvm-ar-15 RANLIB=llvm-ranlib-15 NM=llvm-nm-15 \
 STRIP=llvm-strip-15 CFLAGS="-O3 -pipe" ./configure ${CONFIGURE_ARGS}
make all
make install

ccache --show-stats

apt-get -y remove ${BUILD_DEPS}
apt-get -y autoremove
