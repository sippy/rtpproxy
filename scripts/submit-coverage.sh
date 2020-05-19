#!/bin/sh

set -e

#for ext in gcda gcno
#do
#  find src -name "*_fin.${ext}" -delete
#done

GCOV_CMD="${GCOV_CMD:-gcov}"
coveralls --exclude external --exclude hepconnector --exclude libelperiodic \
  --exclude dist --exclude bench --exclude pertools --gcov "${GCOV_CMD}" \
  --gcov-options '\-lp'
