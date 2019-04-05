#!/bin/sh

set -e

#for ext in gcda gcno
#do
#  find src -name "*_fin.${ext}" -delete
#done

coveralls --exclude external --exclude hepconnector --exclude libelperiodic \
  --exclude bench --exclude pertools --gcov gcov --gcov-options '\-lp'
