#!/bin/sh

set -e
set -x

MYPATH="`realpath "${0}"`"
RTPDIR="`dirname "${MYPATH}"`/.."

CONFIGURE_ARGS="--enable-librtpproxy --enable-noinst=no --enable-silent"
ARCH="`dpkg --print-architecture`"

if [ "${ARCH}" != "armhf" -a "${ARCH}" != "ppc64el" -a "${ARCH}" != "mips64el" ]
then
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-lto=auto"
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

ccache --max-size=250M
ccache --set-config=sloppiness=file_macro
ccache --cleanup
ccache --zero-stats

. "docker/clang_ver.sub"
set_clang_env

CC_VER="`CC="clang-${CLANG_VER}" get_cc_ver`"
if [ "${?}" -ne 0 -o ! -n "${CC_VER}" -o "${CC_VER}" = "68b329da9893e34099c7d8ad5cb9c940" ]
then
  exit 1
fi
export CCACHE_COMPILERCHECK="string:${CC_VER}"

CC=clang-${CLANG_VER} AR=llvm-ar-${CLANG_VER} RANLIB=llvm-ranlib-${CLANG_VER} \
 NM=llvm-nm-${CLANG_VER} STRIP=llvm-strip-${CLANG_VER} CFLAGS="-O3 -pipe" \
 LDFLAGS="-L/usr/local/lib -fuse-ld=lld-${CLANG_VER}" ./configure ${CONFIGURE_ARGS}
make -j4 all
make install

ccache --show-stats

apt-get -y remove --purge ${BUILD_DEPS}
apt-get -y autoremove --purge

find / -xdev -xtype l
find / -xdev -xtype l -delete
