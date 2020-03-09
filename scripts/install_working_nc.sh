#!/bin/sh

wget -O /tmp/nc http://download.sippysoft.com/nc.1.187
chmod 755 /tmp/nc
sudo mv /tmp/nc `which nc`
