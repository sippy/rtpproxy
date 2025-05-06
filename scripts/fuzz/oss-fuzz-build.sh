#!/bin/sh

set -e
set -x
set -o pipefail

CC="${CC:-"clang19"}"
CXX="${CXX:-"${CC}"}"
CFLAGS="${CFLAGS:-"-g3 -O0 -Wall"}"
CXXFLAGS="${CXXFLAGS:-"${CFLAGS}"}"
OUT="${OUT:-"."}"

if [ -z "${LIB_FUZZING_ENGINE}" ]
then
  CFLAGS="${CFLAGS} -DFUZZ_STANDALONE"
  CXXFLAGS="${CXXFLAGS} -DFUZZ_STANDALONE"
fi

install_src_pkg() {
  local PKGNAME="${1}"
  mkdir -p /tmp/src/libfuzzer
  local TMPDIR="`mktemp -d /tmp/src/libfuzzer/${PKGNAME}.XXXXXXXX`"
  local OLD_PWD="`pwd`"
  cd ${TMPDIR}
  apt-get build-dep -y ${PKGNAME}
  apt-get source ${PKGNAME}
  cd ${2}-*
  (head -n 1 debian/rules; \
   echo "export CFLAGS=${CFLAGS}"; \
   echo "export CXXFLAGS=${CXXFLAGS}"; \
   echo "export RANLIB=llvm-ranlib-${CLANG_VER}"; \
   tail -n +2 debian/rules) > debian/_rules
  mv debian/_rules debian/rules
  chmod 755 debian/rules
  ln -sf /usr/bin/true /tmp/dh_dwz
  local PNAME="${PKGNAME}.patch"
  local PPATH="${OLD_PWD}/scripts/fuzz/${PNAME}"
  if [ -e "${PPATH}" ]
  then
    cp "${PPATH}" debian/patches
    echo "${PNAME}" >> debian/patches/series
  fi
  if ! PATH=/tmp:${PATH} DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -uc -us 2>&1 | \
   pv -fl -F "%t %b %p" -i 5 > ../build.log
  then
    tail -n 200 ../build.log
    cd "${OLD_PWD}"
    rm -rf ${TMPDIR}
    exit 1
  fi
  cd -
  dpkg -i *.deb
  cd ${OLD_PWD}
  rm -rf ${TMPDIR}
}

OS="`uname -s`"
if [ "${OS}" != "FreeBSD" ]
then
  . "docker/clang_ver.sub"
  CLANG_VER_OLD=1
  CLANG_VER=18
  APT_INSTALL="apt-get install -y"
  APT_UPDATE="apt-get -y update -qq"
  #apt-get update
  install_clang
  ${APT_INSTALL} file pkg-config llvm-${CLANG_VER} pv
  ldconfig
  perl -pi -e 's|^# deb-src|deb-src|' /etc/apt/sources.list
  ${APT_UPDATE}
  if [ "${SANITIZER}" != "introspector" ]
  then
    install_src_pkg libssl-dev openssl
    install_src_pkg libsrtp2-dev libsrtp2
  else
    ${APT_INSTALL} libsrtp2-dev
  fi
  LIBSRTP="-L/usr/lib/x86_64-linux-gnu \
   -Wl,-Bstatic `pkg-config --libs --static libsrtp2` -lssl -lcrypto \
   -Wl,-Bdynamic -lpthread"
  LLINK_BIN="llvm-link-${CLANG_VER}"
else
  LIBSRTP="-L/usr/local/lib -lsrtp2 -lssl -lcrypto -lpthread"
  LLINK_BIN="llvm-link19"
fi

LD="lld"
LD_BIN="ld.lld"
LDFLAGS="-fuse-ld=${LD}"

CFLAGS="${CFLAGS} -DRTPP_DEBUG_refcnt=1"
CXXFLAGS="${CXXFLAGS} -DRTPP_DEBUG_refcnt=1"

if ! AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip \
 LDFLAGS="${LDFLAGS}" CFLAGS="${CFLAGS}" ./configure --enable-librtpproxy \
  --enable-lto --enable-silent --enable-noinst=no
then
  cat config.log
  exit 1
fi
for dir in libexecinfo libucl libre external/libelperiodic/src libxxHash modules
do
  make -C ${dir} all
done
make -C src librtpproxy.la

CFLAGS="${CFLAGS} -flto -fPIE -fPIC -fvisibility=hidden"
CXXFLAGS="${CXXFLAGS} -flto -fPIE -fPIC -fvisibility=hidden"
RTPPLIB="src/.libs/librtpproxy.a"

for src in rfz_chunk.c rfz_command.c rfz_utils.c
do
  obj="${OUT}/${src%.*}.o"
  src=scripts/fuzz/${src}
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -o ${obj} -c ${src}
  OBJS="${OBJS} ${obj}"
done

ALL="command_parser rtp_parser rtcp_parser rtp_session"
OBJS0="${OBJS}"
for fz in ${ALL}
do
  OBJS="${OBJS0}"
  obj="${OUT}/fuzz_${fz}.o"
  ${CC} ${CFLAGS} ${LIB_FUZZING_ENGINE} -Isrc -Imodules/acct_rtcp_hep \
   -o "${obj}" -c scripts/fuzz/fuzz_${fz}.c

  case "${fz}" in
  rtp_parser)
      LIBRTPP="${RTPPLIB}"
      OBJS="${OBJS} ${obj}"
      ;;
  *)
      _obj="${OUT}/_fuzz_${fz}.o"
      ${LLINK_BIN} -o ${_obj} ${obj} ${RTPPLIB}
      LIBRTPP="${_obj}"
      ;;
  esac

  ${CXX} ${CXXFLAGS} ${LIB_FUZZING_ENGINE} ${LDFLAGS} -o ${OUT}/fuzz_${fz} \
   ${OBJS} ${LIBRTPP} -lm ${LIBSRTP}

  for suff in dict options
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

if [ "${OS}" != "FreeBSD" -a "${SANITIZER}" != "introspector" ]
then
  apt-get reinstall -y libssl1.1
fi
