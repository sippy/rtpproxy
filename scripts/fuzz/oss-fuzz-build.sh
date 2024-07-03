#!/bin/sh

set -e
set -x

CC="${CC:-"clang15"}"
CFLAGS="${CFLAGS:-"-g3 -O0 -Wall"}"
OUT="${OUT:-"."}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-"-DFUZZ_STANDALONE"}"

OS="`uname -s`"
if [ "${OS}" != "FreeBSD" ]
then
  apt-get update
  apt-get install -y libsrtp2-dev file pkg-config
  ldconfig
  #pkg-config --libs --static libsrtp2
  find / -name libsrtp2.so -delete
  LIBSRTP="-L/usr/lib/x86_64-linux-gnu `pkg-config --libs --static libsrtp2`"
else
  LIBSRTP="-L/usr/local/lib -lsrtp2"
fi

./configure --enable-librtpproxy
for dir in libexecinfo libucl libre libelperiodic libxxHash modules/acct_rtcp_hep \
  modules/acct_csv modules/catch_dtmf modules/dtls_gw modules/ice_lite
do
  make -C ${dir} all
done
make -C src librtpproxy.la

for fz in command rtp rtcp
do
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -Imodules/acct_rtcp_hep \
   scripts/fuzz/fuzz_${fz}_parser.c -o ${OUT}/fuzz_${fz}_parser \
   src/.libs/librtpproxy.a -pthread -lm -lssl -lcrypto \
   -L${LIBSRTP}
  for suff in dict options
  do
    if [ -e scripts/fuzz/fuzz_${fz}_parser.${suff} ]
    then
      cp scripts/fuzz/fuzz_${fz}_parser.${suff} ${OUT}
    fi
  done
done
if [ "${OUT}" != "." ]
then
  cp -Rp ${OUT} build-out
fi
