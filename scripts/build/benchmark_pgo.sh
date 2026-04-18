#!/usr/bin/env bash

set -euo pipefail
set -x

CC_BIN="${CC_BIN:-clang}"
PROFDATA_BIN="${PROFDATA_BIN:-llvm-profdata}"
BENCH_SECONDS="${BENCH_SECONDS:-5}"
WORKDIR="${WORKDIR:-build/pgo-bench}"

mkdir -p "${WORKDIR}"

if ! command -v "${CC_BIN}" >/dev/null 2>&1; then
  echo "compiler not found: ${CC_BIN}" >&2
  exit 1
fi
if ! command -v "${PROFDATA_BIN}" >/dev/null 2>&1; then
  echo "profdata tool not found: ${PROFDATA_BIN}" >&2
  exit 1
fi

SRCS=(
  src/spmc_bench_test.c
  src/SPMCQueue.c
)
COMMON_FLAGS=(
  -flto
  -g3
  -O3
  -march=native
  -Wall
  -DNDEBUG
)
LINK_FLAGS=(
  -lpthread
)

BASELINE_BIN="${WORKDIR}/spmc_bench_base"
TRAIN_BIN="${WORKDIR}/spmc_bench_train"
PGO_BIN="${WORKDIR}/spmc_bench_pgo"
PROFRAW_PATTERN="${WORKDIR}/spmc-%p.profraw"
PROFDATA_FILE="${WORKDIR}/spmc.profdata"

parse_mpps() {
  sed -n 's/^PPS is \([0-9.][0-9.]*\) MPPS,.*$/\1/p' | tail -n 1
}

run_bench() {
  local bin="$1"
  "${bin}" -t "${BENCH_SECONDS}"
}

echo "Building baseline benchmark"
"${CC_BIN}" "${COMMON_FLAGS[@]}" "${SRCS[@]}" "${LINK_FLAGS[@]}" -o "${BASELINE_BIN}"
baseline_output="$(run_bench "${BASELINE_BIN}")"
printf '%s\n' "${baseline_output}"
baseline_mpps="$(printf '%s\n' "${baseline_output}" | parse_mpps)"

echo "Building profile-generation benchmark"
"${CC_BIN}" -fprofile-instr-generate "${COMMON_FLAGS[@]}" \
  "${SRCS[@]}" "${LINK_FLAGS[@]}" -o "${TRAIN_BIN}"
rm -f "${WORKDIR}"/spmc-*.profraw "${PROFDATA_FILE}"
LLVM_PROFILE_FILE="${PROFRAW_PATTERN}" run_bench "${TRAIN_BIN}" >/dev/null
"${PROFDATA_BIN}" merge -output="${PROFDATA_FILE}" "${WORKDIR}"/spmc-*.profraw

echo "Building profile-use benchmark"
"${CC_BIN}" -fprofile-instr-use="${PROFDATA_FILE}" "${COMMON_FLAGS[@]}" \
  "${SRCS[@]}" "${LINK_FLAGS[@]}" -o "${PGO_BIN}"
pgo_output="$(run_bench "${PGO_BIN}")"
printf '%s\n' "${pgo_output}"
pgo_mpps="$(printf '%s\n' "${pgo_output}" | parse_mpps)"

python3 - "$baseline_mpps" "$pgo_mpps" <<'PY'
import os
import sys

baseline = float(sys.argv[1])
pgo = float(sys.argv[2])
gain = ((pgo / baseline) - 1.0) * 100.0

summary = (
    "PGO benchmark summary\n"
    f"Baseline: {baseline:.3f} MPPS\n"
    f"PGO: {pgo:.3f} MPPS\n"
    f"Gain: {gain:.2f}%"
)
print(summary)

github_summary = os.environ.get("GITHUB_STEP_SUMMARY")
if github_summary:
    with open(github_summary, "a", encoding="utf-8") as fh:
        fh.write("### PGO Benchmark\n\n")
        fh.write("| Build | MPPS |\n")
        fh.write("| --- | ---: |\n")
        fh.write(f"| Baseline `-O3 -flto -march=native` | {baseline:.3f} |\n")
        fh.write(f"| PGO `-fprofile-instr-use` | {pgo:.3f} |\n")
        fh.write(f"| Gain | {gain:.2f}% |\n")
PY
