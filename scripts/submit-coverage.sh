#!/bin/sh

set -e

for dir in external hepconnector libelperiodic
do
  find ${dir} -name '*.gcda' -delete
done
find src -name '*_fin.gcda' -delete

coveralls --gcov gcov --gcov-options '\-lp';
