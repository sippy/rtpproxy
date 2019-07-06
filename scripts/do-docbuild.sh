#!/bin/sh

set -e

sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" \
 install -y xsltproc fop tidy

./configure
make -C doc clean all
