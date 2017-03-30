#!/bin/sh

set -e

BCG729_VER=1.0.2

uname -a
which ${CC}
${CC} --version
python --version
pip --version
sudo iptables -L OUTPUT
sudo iptables -L INPUT
sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern
./configure
make
make clean
#sudo pip install -r requirements.txt
#sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" \
 install -y libgsm1-dev libsndfile1-dev tcpdump curl wireshark-common
tcpdump --version || true
mkdir deps
cd deps
wget http://download-mirror.savannah.gnu.org/releases/linphone/plugins/sources/bcg729-${BCG729_VER}.tar.gz
tar xfz bcg729-${BCG729_VER}.tar.gz
cd bcg729-${BCG729_VER}
#perl -pi -e 's|BASICOPERATIONSMACROS__H|BASICOPERATIONSMACROS_H|g' include/basicOperationsMacros.h
./configure
make
sudo make install
cd ..
git clone git://github.com/sippy/libg722 libg722
cd libg722
make
sudo make install
cd ../..
git clone https://github.com/cisco/libsrtp.git
cd libsrtp
./configure
make
sudo make install
cd ..
sudo ldconfig
autoreconf --force --install --verbose
./configure
make
TEST_WITNESS_ENABLE=yes make check || (cat tests/test-suite.log; exit 1)
