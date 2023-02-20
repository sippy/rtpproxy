#!/bin/sh

set -e

TEST_WITNESS_ENABLE=yes make check || (cat tests/test-suite.log; exit 1)
