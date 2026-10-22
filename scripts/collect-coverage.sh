#!/bin/sh

set -e

BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${BASEDIR}"

mkdir -p coverage
# lcov 1.x does not recognize the unused-pattern error category.
IGNORE_UNUSED=""
case "$(lcov --version)" in
*"version 1."*) ;;
*) IGNORE_UNUSED="--ignore-errors unused" ;;
esac

# Let gcov supply each file's compilation directory: this build compiles in
# several subdirectories, so a single --base-directory resolves paths wrongly.
# Exclude dependencies during capture, before geninfo validates their counters.
# These sources are omitted from the final report as well.
lcov --capture --directory . --no-external \
  --gcov-tool "${BASEDIR}/scripts/coverage-gcov.sh" \
  --exclude "${BASEDIR}/external/*" --exclude "${BASEDIR}/dist/*" \
  --exclude "${BASEDIR}/bench/*" --exclude "${BASEDIR}/pertools/*" \
  ${IGNORE_UNUSED} \
  --output-file coverage/raw.info

# Some directories have no instrumented sources; newer lcov versions otherwise
# reject unused patterns.
# The combined report includes normal and RTPP_CHECK_LEAKS function variants
# with overlapping source ranges. Preserve their counts when filtering it.
lcov --remove coverage/raw.info ${IGNORE_UNUSED} \
  --rc check_data_consistency=0 \
  "${BASEDIR}/external/*" "${BASEDIR}/dist/*" \
  "${BASEDIR}/bench/*" "${BASEDIR}/pertools/*" \
  --output-file coverage/lcov.info
