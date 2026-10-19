#!/bin/sh

set -e

BASEDIR="`dirname "${0}"`/.."
. "${BASEDIR}/scripts/build/dockerize.sub"
. "${BASEDIR}/scripts/build/build.conf.sub"
. "${BASEDIR}/scripts/functions.sub"

TTYPE="${1}"
BCG729_VER=1.1.2
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
# Image builds cannot change the host kernel's core pattern. Test jobs set it
# before starting the built image.
if [ "${TTYPE}" != "fullbuild" ]
then
  ${SUDO} sysctl -w kernel.core_pattern=core
fi

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
# libsndfile only enables Ogg/Vorbis/FLAC/Opus when their headers are found
${APT_GET} install -y pkg-config libogg-dev libvorbis-dev libflac-dev libopus-dev
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
wget https://github.com/libsndfile/libsndfile/releases/download/${SNDFILE_VER}/libsndfile-${SNDFILE_VER}.tar.xz
if ! which xzcat
then
  apt install -y xz-utils
fi
xzcat libsndfile-${SNDFILE_VER}.tar.xz | ${TAR_CMD} -xv -f -
cd libsndfile-${SNDFILE_VER}
CFLAGS="-std=gnu17" ./configure
# extractaudio tests need Opus output
grep -q '^#define HAVE_EXTERNAL_XIPH_LIBS 1$' src/config.h
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

if [ "${TTYPE}" = "depsbuild" -o "${TTYPE}" = "fullbuild" ]
then
  ./configure ${CONFIGURE_ARGS}
  make ${ALLCLEAN_TGT}
  if ${APT_GET} install -y libsrtp0-dev
  then
    ./configure ${CONFIGURE_ARGS}
    make ${ALLCLEAN_TGT}
  fi
  if [ "${TTYPE}" = "depsbuild" ]
  then
    exit 0
  fi
fi

build_tests() {
  case ${1} in
  basic)
    TEST_CONFIGURE_ARGS="--enable-basic-tests"
    ;;

  glitching)
    TEST_CONFIGURE_ARGS="--disable-basic-tests --enable-memglitching"
    ;;

  *)
    echo "Unknown or undefined TTYPE" >&2
    exit 1
    ;;
  esac

  ./configure ${CONFIGURE_ARGS} --enable-coverage ${TEST_CONFIGURE_ARGS}
  make clean all
}

if [ "${TTYPE}" = "fullbuild" ]
then
  # Keep separate configured source trees so both suites use exactly the same
  # binaries and coverage paths that were produced here, without reconfiguring.
  for suite in basic glitching
  do
    TEST_DIR="/opt/rtpproxy/${suite}"
    mkdir -p "${TEST_DIR}"
    cp -a . "${TEST_DIR}/"
    (cd "${TEST_DIR}" && build_tests "${suite}")
  done
else
  build_tests "${TTYPE}"
fi

UDPR_DIR=/tmp/dist/udpreplay

git clone -b master https://github.com/sippy/udpreplay.git ${UDPR_DIR}
mkdir ${UDPR_DIR}/build
cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -B${UDPR_DIR}/build -H${UDPR_DIR}
make -C ${UDPR_DIR}/build all
${SUDO} make -C ${UDPR_DIR}/build install

tcpdump --version || true
