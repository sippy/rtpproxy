#!/bin/sh

set -e

PYTHON_CMD="${PYTHON_CMD:-"python${PY_VER}"}"

${PYTHON_CMD} -m ensurepip --upgrade
${PYTHON_CMD} -m pip install --upgrade pip
${PYTHON_CMD} -m pip install --upgrade build setuptools wheel auditwheel
