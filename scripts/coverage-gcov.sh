#!/bin/sh

set -e

. "$(dirname "$0")/build/build.conf.sub"

# GCOV_CMD may include a subcommand, for example "llvm-cov-18 gcov".
exec ${GCOV_CMD:-gcov} "$@"
