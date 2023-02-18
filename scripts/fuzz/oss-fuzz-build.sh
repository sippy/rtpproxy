#!/bin/sh

set -e
set -x

CC="${CC:-"clang15"}"
CFLAGS="${CFLAGS:-"-g3 -O0 -Wall"}"
OUT="${OUT:-"."}"

./configure
make -C libexecinfo all
make -C libucl all
make -C libelperiodic all
make -C modules/acct_rtcp_hep all
make -C src rtpproxy

rm src/*-main.o
rm src/*-rtpp_netio_async.o
rm src/*-rtpp_socket.o
ar -r librtpproxy.a ./src/*.o ./modules/acct_rtcp_hep/*.o

for fz in command rtp rtcp
do
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -Imodules/acct_rtcp_hep \
   scripts/fuzz/fuzz_${fz}_parser.c -o ${OUT}/fuzz_${fz}_parser \
   librtpproxy.a libucl/libucl.a -pthread
done
cp -Rp ${OUT} build-out
