#!/bin/sh

set -e

BASEDIR="`dirname "${0}"`/.."
. "${BASEDIR}/scripts/build/dockerize.sub"
. "${BASEDIR}/scripts/build/build.conf.sub"
. "${BASEDIR}/scripts/functions.sub"

TTYPE="${1}"
BCG729_VER=1.1.1
SNDFILE_VER=1.2.2

TAR_CMD=${TAR_CMD:-"tar"}

uname -a
which ${CC}
${CC} --version
python3 --version
automake --version
autoconf --version
autoreconf --version

echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern
${SUDO} sysctl -w kernel.core_pattern=core

ALLCLEAN_TGT="all clean distclean"

if [ ! -z "${CC_EXTRA_OPTS}" ]
then
  export CC="${CC} ${CC_EXTRA_OPTS}"
fi

if [ "${TTYPE}" = "cleanbuild" ]
then
  if [ -n "${DOCKR_PLATFORM}" ]
  then
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --host=${DOCKR_PLATFORM}-pc-linux-gnu"
  fi
  ./configure ${CONFIGURE_ARGS}
  exec make ${ALLCLEAN_TGT}
fi

${APT_GET} install -y libgsm1-dev libpcap-dev cmake libunwind-dev tcpdump curl \
 gdb tcpreplay ffmpeg
OPWD="`pwd`"
mkdir /tmp/deps
cd /tmp/deps
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
wget https://ftp2.osuosl.org/pub/blfs/conglomeration/libsndfile/libsndfile-${SNDFILE_VER}.tar.xz
if ! which xzcat
then
  apt install -y xz-utils
fi
xzcat libsndfile-${SNDFILE_VER}.tar.xz | ${TAR_CMD} -xv -f -
cd libsndfile-${SNDFILE_VER}
CFLAGS="-std=gnu17" ./configure
make
${SUDO} make install
cd ${OPWD}

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

UDPR_DIR=/tmp/dist/udpreplay

git clone -b master https://github.com/sippy/udpreplay.git ${UDPR_DIR}
mkdir ${UDPR_DIR}/build
cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -B${UDPR_DIR}/build -H${UDPR_DIR}
make -C ${UDPR_DIR}/build all
${SUDO} make -C ${UDPR_DIR}/build install

tcpdump --version || true
