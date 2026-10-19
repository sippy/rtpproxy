#!/bin/sh

set -e

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

# Older Ubuntu releases bundle compiler-rt with libclang-common. Only install
# the separate runtime package if the selected compiler cannot link coverage.
case "${COMPILER}" in
clang|clang-*)
  CLANG_RT_TEST=$(mktemp -d)
  printf 'int main(void) { return 0; }\n' > "${CLANG_RT_TEST}/test.c"
  if ! ${CC} --coverage "${CLANG_RT_TEST}/test.c" -o "${CLANG_RT_TEST}/test"
  then
    CLANG_MAJOR=$(${CC} -dumpversion | cut -d. -f1)
    ${SUDO} apt-get -y install "libclang-rt-${CLANG_MAJOR}-dev"
    ${CC} --coverage "${CLANG_RT_TEST}/test.c" -o "${CLANG_RT_TEST}/test"
  fi
  rm -rf "${CLANG_RT_TEST}"
  ;;
esac

${SUDO} apt-get -y install python3-pip python3-dev lcov
PIP_RUN="python3 -m pip"
${SUDO} find /usr/lib -type f -name 'EXTERNALLY-MANAGED' -delete
${PIP_RUN} install --user -U pip setuptools
which python3
python3 --version
for pkg in parsimonious
do
  ${PIP_RUN} install ${pkg}
done
${PIP_RUN} install -r python/tools/requirements.txt
