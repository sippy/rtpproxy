#!/bin/sh

set -e
set -x

sudo gem install apt-spy2
sudo apt-spy2 check --strict --country=US
sudo apt-spy2 fix --commit --strict --country=US
