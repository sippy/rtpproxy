#!/bin/sh

set -e
set -x

uname -a
ARCH=`uname -m`
COMPILER=${COMPILER:-gcc}
. $(dirname $0)/build.conf.sub

${CC} --version

_TCMD="/usr/bin/time"

linux_time()
{
  "${_TCMD}" -f "\t%e real\t%U user\t%s sys" "${@}"
}

if "${_TCMD}" -f "" echo 2>/dev/null >/dev/null
then
  TCMD="linux_time"
else
  TCMD="${_TCMD}"
fi

if ${PYTHON_CMD} -m build --sdist
then
  ${PYTHON_CMD} -m build --wheel
else
  ${PYTHON_CMD} setup.py build
  ${PYTHON_CMD} setup.py sdist
  ${PYTHON_CMD} setup.py bdist_wheel
fi
if [ ! -e "${PYTHON_CMD}" ]
then
  PYTHON_CMD=`which ${PYTHON_CMD}`
fi
${SUDO} ${PYTHON_CMD} -m pip install .

${TCMD} -o ElPeriodic.timings ${PYTHON_CMD} tests/t_ElPeriodic.py
