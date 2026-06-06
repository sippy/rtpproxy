#!/bin/sh

set -e

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get -y install python3-pip python3-dev
PIP_RUN="python3 -m pip"
${SUDO} find /usr/lib -type f -name 'EXTERNALLY-MANAGED' -delete
${PIP_RUN} install --user -U pip setuptools
which python3
python3 --version
for pkg in parsimonious cpp-coveralls
do
  ${PIP_RUN} install ${pkg}
done
${PIP_RUN} install -r python/tools/requirements.txt
