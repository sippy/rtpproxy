#!/bin/sh

set -e
set -x

sudo -H DEBIAN_FRONTEND=noninteractive apt-get update --fix-missing
