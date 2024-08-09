#!/bin/sh

set -e
set -x

CC="${CC:-"clang15"}"
CFLAGS="${CFLAGS:-"-g3 -O0 -Wall"}"
OUT="${OUT:-"."}"

if [ -z "${LIB_FUZZING_ENGINE}" ]
then
  CFLAGS="${CFLAGS} -DFUZZ_STANDALONE"
fi

OS="`uname -s`"
if [ "${OS}" != "FreeBSD" ]
then
  apt-get update
  apt-get install -y libsrtp2-dev file pkg-config
  ldconfig
  find / -name libsrtp2.so -delete
  LIBSRTP="-L/usr/lib/x86_64-linux-gnu `pkg-config --libs --static libsrtp2` -lssl -lcrypto"
else
  LIBSRTP="-L/usr/local/lib -lsrtp2 -lssl -lcrypto"
fi


AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip \
 ./configure --enable-librtpproxy --enable-lto
for dir in libexecinfo libucl libre libelperiodic/src libxxHash modules
do
  make -C ${dir} all
done
make -C src librtpproxy.la

CFLAGS="${CFLAGS} -flto"

ALL="command_parser rtp_parser rtcp_parser rtp_session"

for fz in ${ALL}
do
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -Imodules/acct_rtcp_hep \
   -o ${OUT}/fuzz_${fz} \
   -Wl,--version-script=scripts/fuzz/Symbol.map -fPIE -pie \
   scripts/fuzz/fuzz_${fz}.c \
   -Wl,--whole-archive src/.libs/librtpproxy.a -Wl,--no-whole-archive \
   -pthread -lm ${LIBSRTP}
  for suff in dict options setup
  do
    if [ -e scripts/fuzz/fuzz_${fz}.${suff} ]
    then
      cp scripts/fuzz/fuzz_${fz}.${suff} ${OUT}
    fi
  done
done
if [ "${OUT}" != "." ]
then
  cp -Rp ${OUT} build-out
fi
