#!/bin/sh

set -e

sudo -H DEBIAN_FRONTEND=noninteractive apt-get update
sudo apt-get -y install python3-pip python-dev
sudo pip3 install -U pip setuptools wheel
#sudo pip3 install -U virtualenvwrapper
which python
python --version
pip3 install --user elperiodic
pip3 install --user cpp-coveralls
