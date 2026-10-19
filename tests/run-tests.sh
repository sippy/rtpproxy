#!/bin/sh

# Run the serial test suite with live output and a final failure summary.
# Exit codes follow Automake's serial-tests conventions (77 means SKIP).

total=0
pass=0
fail=0
skip=0
failures=

# Do not leave a previous run's results behind, including for an empty suite.
: > test-suite.log || exit 1

for test_name do
    if test -f "./${test_name}"; then
        test_path="./${test_name}"
    elif test -f "${test_name}"; then
        test_path="${test_name}"
    else
        test_path="${srcdir}/${test_name}"
    fi

    if "${test_path}"; then
        status=0
    else
        status=$?
    fi
    total=$((total + 1))
    if test "${status}" -eq 77; then
        result=SKIP
        skip=$((skip + 1))
    elif test "${status}" -eq 0; then
        result=PASS
        pass=$((pass + 1))
    else
        result=FAIL
        fail=$((fail + 1))
    fi

    printf '%s: %s\n' "${result}" "${test_name}"
    case "${result}" in
    FAIL)
        failures="${failures}${result}: ${test_name}
"
        ;;
    esac
done

{
    printf '%s\n' '======================================' 'Testsuite summary'
    printf 'TOTAL: %s\nPASS:  %s\nSKIP:  %s\nFAIL:  %s\n' \
      "${total}" "${pass}" "${skip}" "${fail}"
    if test -n "${failures}"; then
        printf '\nFailed tests:\n%s' "${failures}"
    fi
    printf '%s\n' '======================================'
} > test-suite.log || exit 1
cat test-suite.log || exit 1

test "${fail}" -eq 0
