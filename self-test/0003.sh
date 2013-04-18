#!/bin/sh

python 0003.py > /tmp/0003.sip
diff -dubB 0003.sip /tmp/0003.sip

