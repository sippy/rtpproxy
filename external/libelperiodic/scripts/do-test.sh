#!/bin/sh

set -e
set -x

uname -a
ARCH=`uname -m`
COMPILER=${COMPILER:-gcc}
. $(dirname $0)/build.conf.sub

${CC} --version

_TCMD="/usr/bin/time"

linux_time()
{
  "${_TCMD}" -f "\t%e real\t%U user\t%s sys" "${@}"
}

if "${_TCMD}" -f "" echo 2>/dev/null >/dev/null
then
  TCMD="linux_time"
else
  TCMD="${_TCMD}"
fi

./configure --without-python
make all
./configure --without-python --enable-coverage
make clean all
${SUDO} make install

${SUDO} ldconfig

cd src

for badargs in '--foobar' '-?' 'x'
do
  ./testskew ${badarg} 2>/dev/null && false
done

for arg in '' '-w' '-p' '-p -w'
do
  ./testskew ${arg} -m 997.983 0.1
  ./testskew ${arg} -L 200 5
  ./testskew ${arg} 10 5.0 20 2.5 40 2.5 80 2.5 160 2.5 320 2.5
  ./testskew ${arg} -f 0.75 -v 0.1 100
  sh ./findskew.sh ${arg}
done
