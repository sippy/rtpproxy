#!/bin/sh

set -e

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get -y install python3-pip python3-dev
PIP_RUN="python -m pip"
${PIP_RUN} install --user -U pip setuptools
which python
python --version
for pkg in parsimonious cpp-coveralls
do
  ${PIP_RUN} install --user ${pkg}
done
${PIP_RUN} install --user -r python/tools/requirements.txt
