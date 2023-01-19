#!/bin/sh

set -e
set -x

if [ "${GHA_OS}" = "ubuntu-18.04" ]
then
  sudo gem install apt-spy2 -v 0.7.2
else
  sudo gem install apt-spy2
fi
sudo apt-spy2 check
sudo apt-spy2 fix --commit
sudo -H DEBIAN_FRONTEND=noninteractive apt-get update
