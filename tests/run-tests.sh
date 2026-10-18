#!/bin/sh

# Run the serial test suite with live output and a final failure summary.
# Exit codes follow Automake's serial-tests conventions (77 means SKIP).

total=0
pass=0
fail=0
skip=0
xfail=0
xpass=0
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

    expected_failure=no
    for expected_test in ${XFAIL_TESTS-}; do
        if test "${expected_test}" = "${test_name}"; then
            expected_failure=yes
            break
        fi
    done

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
        if test "${expected_failure}" = yes; then
            result=XPASS
            xpass=$((xpass + 1))
        else
            result=PASS
            pass=$((pass + 1))
        fi
    elif test "${expected_failure}" = yes; then
        result=XFAIL
        xfail=$((xfail + 1))
    else
        result=FAIL
        fail=$((fail + 1))
    fi

    printf '%s: %s\n' "${result}" "${test_name}"
    case "${result}" in
    FAIL|XPASS)
        failures="${failures}${result}: ${test_name}
"
        ;;
    esac
done

{
    printf '%s\n' '======================================' 'Testsuite summary'
    printf 'TOTAL: %s\nPASS:  %s\nSKIP:  %s\nXFAIL: %s\nFAIL:  %s\nXPASS: %s\n' \
      "${total}" "${pass}" "${skip}" "${xfail}" "${fail}" "${xpass}"
    if test -n "${failures}"; then
        printf '\nFailed tests:\n%s' "${failures}"
    fi
    printf '%s\n' '======================================'
} > test-suite.log || exit 1
cat test-suite.log || exit 1

# GitHub publishes this Markdown on the workflow run's summary page, even
# when the test step fails. Local runs do not need any GitHub-specific setup.
if test -n "${GITHUB_STEP_SUMMARY-}"; then
    {
        printf '### Test suite\n\n'
        if test -n "${GHA_OS-}${COMPILER-}"; then
            printf 'Environment: `%s` / `%s`\n\n' \
              "${GHA_OS-unknown}" "${COMPILER-unknown}"
        fi
        printf '| Total | Passed | Skipped | Expected failures | Failed | Unexpected passes |\n'
        printf '| ---: | ---: | ---: | ---: | ---: | ---: |\n'
        printf '| %s | %s | %s | %s | %s | %s |\n\n' \
          "${total}" "${pass}" "${skip}" "${xfail}" "${fail}" "${xpass}"
        if test -n "${failures}"; then
            printf '#### Failed tests\n\n```text\n%s```\n\n' "${failures}"
        else
            printf 'No unexpected failures.\n\n'
        fi
    } >> "${GITHUB_STEP_SUMMARY}" || exit 1
fi

test "$((fail + xpass))" -eq 0
