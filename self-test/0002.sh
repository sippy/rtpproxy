#!/bin/sh

python 0002.py > /tmp/0002.sip
diff -dubB 0002.sip /tmp/0002.sip

