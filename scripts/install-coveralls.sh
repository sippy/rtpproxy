#!/bin/sh

# Fetch a pinned Coveralls coverage reporter into a directory, so that CI can
# cache it rather than have every coverage job download it from GitHub.

set -e

VERSION="${1}"
DEST="${2}"
TARBALL="coveralls-linux-x86_64.tar.gz"
URL="https://github.com/coverallsapp/coverage-reporter/releases/download/${VERSION}"

mkdir -p "${DEST}"
cd "${DEST}"
curl -fsSL --retry 5 --retry-all-errors -O "${URL}/${TARBALL}" \
  -O "${URL}/coveralls-checksums.txt"
grep " ${TARBALL}\$" coveralls-checksums.txt | sha256sum -c -
tar -xzf "${TARBALL}"
rm "${TARBALL}" coveralls-checksums.txt
test -x coveralls
