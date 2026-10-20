#!/bin/sh

set -e

# LLVM's development archives are particularly large. Keep the compiler,
# gcov/llvm-cov, make and Git for coverage and the autosrc consistency test.
# Do not autoremove: libraries installed with development packages may also
# be used by the test binaries or locally built dependencies.
dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' | \
  awk '$2 == "installed" && $1 ~ /^(llvm(-[0-9]+)?-dev|libc\+\+(-[0-9]+)?-dev|libc\+\+abi(-[0-9]+)?-dev|python3(-dev|\.[0-9]+-dev)|libpython3(-dev|\.[0-9]+-dev)|cmake|cmake-data)(:[^ ]+)?$/ {print $1}' \
  > /tmp/ci-build-packages
if [ -s /tmp/ci-build-packages ]
then
  xargs apt-get purge -y < /tmp/ci-build-packages
fi
rm -f /tmp/ci-build-packages

# Keep .gcno files for coverage, shared libraries and executable debug symbols
# for glitch diagnostics. Only the prebuilt test targets run in this image.
find /opt/rtpproxy -type f \( -name '*.o' -o -name '*.a' \) -delete
find /usr/local/lib -type f -name '*.a' -delete

echo "Largest installed packages after CI image cleanup (KiB):"
dpkg-query -W -f='${Installed-Size}\t${binary:Package}\n' | sort -nr | head -20
