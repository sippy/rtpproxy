#!/bin/sh

set -e

BASEDIR="`dirname "${0}"`/.."
. "${BASEDIR}/scripts/build/dockerize.sub"
. "${BASEDIR}/scripts/build/build.conf.sub"
. "${BASEDIR}/scripts/functions.sub"

TTYPE="${1}"
BCG729_VER=1.1.1
SNDFILE_VER=1.0.28

TAR_CMD=${TAR_CMD:-"tar"}

uname -a
which ${CC}
${CC} --version
python3 --version
automake --version
autoconf --version
autoreconf --version

if [ "${TTYPE}" != "depsbuild" -a "${TTYPE}" != "cleanbuild" ]
then
  ${SUDO} iptables -w -L OUTPUT
  ${SUDO} iptables -w -L INPUT
  ${SUDO} sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
fi
echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern

ALLCLEAN_TGT="all clean distclean"

if [ ! -z "${CC_EXTRA_OPTS}" ]
then
  export CC="${CC} ${CC_EXTRA_OPTS}"
fi

if [ "${TTYPE}" = "cleanbuild" ]
then
  ./configure ${CONFIGURE_ARGS}
  exec make ${ALLCLEAN_TGT}
fi

${APT_GET} install -y libgsm1-dev libpcap-dev cmake libunwind-dev tcpdump curl \
 gdb tcpreplay ffmpeg
mkdir deps
cd deps
wget -O bcg729-${BCG729_VER}.tar.gz \
  https://github.com/BelledonneCommunications/bcg729/archive/${BCG729_VER}.tar.gz
${TAR_CMD} xfz bcg729-${BCG729_VER}.tar.gz
cd bcg729-${BCG729_VER}
touch ChangeLog NEWS AUTHORS
perl -pi -e 's|bcg729.spec||g' configure.ac
./autogen.sh
./configure
make
${SUDO} make install
cd ..
git clone https://github.com/sippy/libg722 libg722
cd libg722
make
${SUDO} make install
cd ..
git clone -b 2_x_dev https://github.com/cisco/libsrtp.git
cd libsrtp
./configure
make
${SUDO} make install
cd ..
wget http://www.mega-nerd.com/libsndfile/files/libsndfile-${SNDFILE_VER}.tar.gz
${TAR_CMD} xfz libsndfile-${SNDFILE_VER}.tar.gz
cd libsndfile-${SNDFILE_VER}
./configure
make
${SUDO} make install
cd ../..

${SUDO} ldconfig

if ! autoreconf --force --install --verbose 2>/tmp/auto.log
then
  if ! grep -q 'higher is required' /tmp/auto.log
  then
    cat /tmp/auto.log >&2
    exit 1
  fi
fi

if [ "${TTYPE}" = "depsbuild" ]
then
  ./configure ${CONFIGURE_ARGS}
  make ${ALLCLEAN_TGT}
  if ${APT_GET} install -y libsrtp0-dev
  then
    ./configure ${CONFIGURE_ARGS}
    exec make ${ALLCLEAN_TGT}
  else
    exit 0
  fi
fi

CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-coverage"
case ${TTYPE} in
basic)
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-basic-tests"
  ;;

glitching)
  CONFIGURE_ARGS="${CONFIGURE_ARGS} --disable-basic-tests --enable-memglitching"
  ;;

*)
  echo "Unknown or undefined TTYPE" >&2
  exit 1
  ;;
esac

./configure ${CONFIGURE_ARGS}
make clean all

ELP_BRANCH="${ELP_BRANCH:-"master"}"
cd deps
git clone --branch ${ELP_BRANCH} https://github.com/sobomax/libelperiodic.git
cd libelperiodic
./configure --without-python
make all
${SUDO} make install
cd ../..

${SUDO} ldconfig

git clone -b master https://github.com/sippy/udpreplay.git dist/udpreplay
mkdir dist/udpreplay/build
cmake -Bdist/udpreplay/build -Hdist/udpreplay
make -C dist/udpreplay/build all
${SUDO} make -C dist/udpreplay/build install

tcpdump --version || true
