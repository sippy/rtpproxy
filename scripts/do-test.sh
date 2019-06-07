#!/bin/sh

set -e

uname -a
which ${CC}
${CC} --version
python3 --version
sudo iptables -L OUTPUT
sudo iptables -L INPUT
sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern

sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" \
 install -y xsltproc fop

./configure
make -C doc clean all
mkdir -p docdeploy/${TRAVIS_BRANCH}
cp doc/*.html docdeploy/${TRAVIS_BRANCH}
