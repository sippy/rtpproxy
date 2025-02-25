#!/bin/sh

set -e

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get -y install python3-pip python3-dev
${SUDO} pip3 install --user -U pip setuptools
which python
python --version
for pkg in parsimonious elperiodic cpp-coveralls
do
  pip3 install --user ${pkg}
done
