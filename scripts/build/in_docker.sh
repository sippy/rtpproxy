#!/bin/bash

set -e

ENV="`${SET_ENV}`"
ARGS="${@}"
if [ "${?}" -ne 0 ]
then
  exit "${?}"
fi
IFS=$'\n' && set -- ${ENV} && IFS=''
env "${@}" ${ARGS}
