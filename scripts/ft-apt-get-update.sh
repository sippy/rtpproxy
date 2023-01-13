#!/bin/sh

set -e
set -x

if [ "${GHA_OS}" != "ubuntu-18.04" ]
then
  sudo gem install apt-spy2
  sudo apt-spy2 check --strict
  sudo apt-spy2 fix --commit --strict
fi

sudo -H DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing
