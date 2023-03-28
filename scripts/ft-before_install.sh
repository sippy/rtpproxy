#!/bin/sh

set -e

. $(dirname $0)/build/dockerize.sub
. $(dirname $0)/build/build.conf.sub

${SUDO} apt-get -y install python3-pip python3-dev
${SUDO} pip3 install -U pip setuptools wheel
#${SUDO} pip3 install -U virtualenvwrapper
which python
python --version
pip3 install --user elperiodic
pip3 install --user cpp-coveralls
