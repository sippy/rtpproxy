#!/bin/sh

set -e

BASEDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${BASEDIR}"

# The coverage sanitizer replays OSS-Fuzz corpora and leaves a merged LLVM
# profile in cifuzz-coverage. Use OSS-Fuzz's LLVM tools to read its format.
test -s cifuzz-coverage/dumps/merged.profdata
set --
for target in build-out/fuzz_*
do
  if [ -f "${target}" ] && [ -x "${target}" ]
  then
    set -- "$@" "-object=/out/${target##*/}"
  fi
done
if [ "$#" -eq 0 ]
then
  echo "No coverage fuzzers found in build-out" >&2
  exit 1
fi

mkdir -p coverage
docker run --rm \
  -v "${BASEDIR}/build-out:/out:ro" \
  -v "${BASEDIR}/cifuzz-coverage:/coverage:ro" \
  --entrypoint llvm-cov gcr.io/oss-fuzz-base/base-runner \
  export -format=lcov -instr-profile=/coverage/dumps/merged.profdata "$@" \
  > coverage/raw.info

python3 scripts/fuzz/normalize-coverage.py
