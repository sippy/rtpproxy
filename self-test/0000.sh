#!/bin/sh

python 0000.py > /tmp/0000.sip
diff -dubB 0000.sip /tmp/0000.sip

