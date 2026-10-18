#!/bin/sh

set -e

BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${BASEDIR}"

mkdir -p coverage
lcov --capture --directory . --base-directory "${BASEDIR}" --no-external \
  --gcov-tool "${BASEDIR}/scripts/coverage-gcov.sh" \
  --output-file coverage/raw.info

# Keep the exclusions used by submit-coverage.sh. Some directories may have
# no instrumented sources; newer lcov versions otherwise reject unused patterns.
# The combined report includes normal and RTPP_CHECK_LEAKS function variants
# with overlapping source ranges. Preserve their counts when filtering it.
lcov --remove coverage/raw.info --ignore-errors unused \
  --rc check_data_consistency=0 \
  "${BASEDIR}/external/*" "${BASEDIR}/hepconnector/*" \
  "${BASEDIR}/libelperiodic/*" "${BASEDIR}/dist/*" \
  "${BASEDIR}/bench/*" "${BASEDIR}/pertools/*" \
  --output-file coverage/lcov.info
