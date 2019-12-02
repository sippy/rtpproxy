#!/bin/sh

set -e

BASEDIR="`dirname "${0}"`/.."
. "${BASEDIR}/scripts/functions.sub"

TTYPE="${1}"
BCG729_VER=1.0.4
SNDFILE_VER=1.0.28

uname -a
which ${CC}
${CC} --version
python3 --version
sudo iptables -L OUTPUT
sudo iptables -L INPUT
sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern
${APT_GET} install -y libgsm1-dev tcpdump curl wireshark-common gdb
tcpdump --version || true
mkdir deps
cd deps
wget https://linphone.org/releases/sources/bcg729/bcg729-${BCG729_VER}.tar.gz
tar xfz bcg729-${BCG729_VER}.tar.gz
cd bcg729-${BCG729_VER}
#perl -pi -e 's|BASICOPERATIONSMACROS__H|BASICOPERATIONSMACROS_H|g' include/basicOperationsMacros.h
./autogen.sh
./configure
make
sudo make install
cd ..
git clone git://github.com/sippy/libg722 libg722
cd libg722
make
sudo make install
cd ..
git clone https://github.com/cisco/libsrtp.git
cd libsrtp
./configure
make
sudo make install
cd ..
wget http://www.mega-nerd.com/libsndfile/files/libsndfile-${SNDFILE_VER}.tar.gz
tar xfz libsndfile-${SNDFILE_VER}.tar.gz
cd libsndfile-${SNDFILE_VER}
./configure
make
sudo make install
cd ../..

sudo ldconfig

autoreconf --force --install --verbose

CONFIGURE_ARGS="--enable-coverage"
case ${TTYPE} in
basic)
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-basic-tests"
  ;;

glitching)
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-memglitching"
  ;;

*)
  echo "Unknown or indefined TTYPE" >&2
  exit 1
  ;;
esac

./configure ${CONFIGURE_ARGS}
make clean all

cd deps
git clone git://github.com/sobomax/libelperiodic.git
cd libelperiodic
./configure
make all
sudo make install
sudo python3 setup.py build install
cd ../..

sudo ldconfig

${APT_GET} install -y libpcap-dev cmake
git clone -b precise_timings https://github.com/sippy/udpreplay.git dist/udpreplay
mkdir dist/udpreplay/build
cmake -Bdist/udpreplay/build -Hdist/udpreplay
make -C dist/udpreplay/build all
sudo make -C dist/udpreplay/build install

TEST_WITNESS_ENABLE=yes make check || (cat tests/test-suite.log; exit 1)
