#!/bin/sh

python 0001.py > /tmp/0001.sip
diff -dubB 0001.sip /tmp/0001.sip

