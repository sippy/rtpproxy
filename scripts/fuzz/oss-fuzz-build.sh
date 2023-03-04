#!/bin/sh

set -e
set -x

CC="${CC:-"clang15"}"
CFLAGS="${CFLAGS:-"-g3 -O0 -Wall"}"
OUT="${OUT:-"."}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-"-DFUZZ_STANDALONE"}"

./configure --enable-librtpproxy
make -C libexecinfo all
make -C libucl all
make -C libelperiodic all
make -C modules/acct_rtcp_hep all
make -C src librtpproxy.a

ar -r librtcp.a ./modules/acct_rtcp_hep/*.o

for fz in command rtp rtcp
do
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -Imodules/acct_rtcp_hep \
   scripts/fuzz/fuzz_${fz}_parser.c -o ${OUT}/fuzz_${fz}_parser \
   src/librtpproxy.a libucl/libucl.a libelperiodic/src/.libs/libelperiodic.a \
   librtcp.a -pthread -lm
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
