#!/bin/sh

set -e

for ext in gcda gcno
do
  for dir in external hepconnector libelperiodic
  do
    find ${dir} -name "*.${ext}"' -delete
  done
  find src -name "*_fin.${ext}" -delete
done

coveralls --gcov gcov --gcov-options '\-lp';
