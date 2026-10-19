#!/usr/bin/env python3
"""Collect matrix test results and render one GitHub Actions summary."""

import argparse
import html
import itertools
import json
import os
from pathlib import Path
import re


COUNTS = ("TOTAL", "PASS", "SKIP", "FAIL")


def output_name(os_name, compiler):
    return re.sub(r"[^A-Za-z0-9_]", "_", "result_" + os_name + "_" + compiler)


def generate(args):
    # YAML is only needed for workflow maintenance, not for collecting results.
    import yaml

    source = args.workflow.read_text()
    workflow = yaml.safe_load(source)
    updated = source
    for name, job in workflow["jobs"].items():
        if not any(step.get("id") == "summary" for step in job.get("steps", [])):
            continue
        matrix = job["strategy"]["matrix"]
        combinations = [dict(os=os_name, compiler=compiler)
                        for os_name, compiler in itertools.product(matrix["os"], matrix["compiler"])]
        combinations = [row for row in combinations if not any(
            all(row.get(key) == value for key, value in excluded.items())
            for excluded in matrix.get("exclude", []))]
        combinations += matrix.get("include", [])
        keys = list(dict.fromkeys(output_name("ubuntu-" + str(row["os"]), row["compiler"])
                                  for row in combinations))
        begin = "    # BEGIN GENERATED TEST OUTPUTS: " + name
        end = "    # END GENERATED TEST OUTPUTS: " + name
        block = begin + "\n    # Regenerate: python3 scripts/test-summary.py generate\n    outputs:\n"
        block += "".join("      " + key + ": ${{ steps.summary.outputs." + key + " }}\n"
                         for key in keys)
        block += end
        pattern = re.escape(begin) + r"\n.*?" + re.escape(end)
        updated, count = re.subn(pattern, lambda match: block, updated, flags=re.S)
        if count != 1:
            raise ValueError("Expected one generated output block for " + name)
    if args.check:
        if updated != source:
            raise SystemExit("Test outputs are stale; run: python3 scripts/test-summary.py generate")
    else:
        args.workflow.write_text(updated)


def collect(args):
    result = {
        "suite": args.suite,
        "os": os.environ.get("GHA_OS", "unknown"),
        "compiler": os.environ.get("COMPILER", "unknown"),
        "outcome": os.environ.get("TEST_OUTCOME", "unknown"),
        "job_outcome": os.environ.get("JOB_OUTCOME", os.environ.get("TEST_OUTCOME", "unknown")),
        "counts": {},
        "failures": [],
    }
    # A build/setup failure may skip tests and leave a stale suite log.
    if result["outcome"] in ("success", "failure") and args.log.is_file():
        for line in args.log.read_text().splitlines():
            match = re.fullmatch(r"(TOTAL|PASS|SKIP|FAIL):\s+(\d+)", line)
            if match:
                result["counts"][match[1]] = int(match[2])
            elif line.startswith("FAIL: "):
                result["failures"].append(line)
    if set(result["counts"]) != set(COUNTS):
        result["counts"] = {}
    encoded = json.dumps(result, separators=(",", ":"))
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        name = output_name(result["os"], result["compiler"])
        with Path(output_file).open("a") as output:
            output.write(name + "=" + encoded + "\n")
    else:
        print(encoded)


def cell(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ")


def render(args):
    jobs = json.loads(os.environ.get("TEST_RESULTS", "{}"))
    results = [json.loads(value) for job in jobs.values()
               for value in job.get("outputs", {}).values() if value]
    results.sort(key=lambda row: (row["suite"], row["os"], row["compiler"]))
    print("## Test results\n")
    if not results:
        print("No test results were reported. Check the build and test job logs.")
        return
    print("| Suite | OS | Compiler | Job result | Test result | Total | Passed | Skipped | Failed | Failed tests |")
    print("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |")
    for row in results:
        counts = row["counts"]
        if row["outcome"] in ("skipped", "cancelled"):
            outcome = "Tests " + row["outcome"]
        elif not counts:
            outcome = "No completed test suite"
        elif row["outcome"] != "success" or counts["FAIL"]:
            outcome = "FAIL"
        else:
            outcome = "PASS"
        job_outcome = {"success": "PASS", "failure": "FAIL", "skipped": "SKIP",
                       "cancelled": "CANCELLED"}.get(row.get("job_outcome", row["outcome"]), "—")
        cells = [cell(row[key]) for key in ("suite", "os", "compiler")]
        cells += [job_outcome, outcome] + [str(counts.get(key, "—")) for key in COUNTS]
        cells += ["<br>".join("<code>" + cell(name) + "</code>" for name in row["failures"]) or "—"]
        print("| " + " | ".join(cells) + " |")
    print("\nJob result includes coverage collection and upload. Tests skipped before execution usually indicate a build or setup failure.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generator = commands.add_parser("generate", help="regenerate workflow outputs (requires PyYAML)")
    generator.add_argument("--workflow", type=Path, default=Path(".github/workflows/rtpproxy_ci.yml"))
    generator.add_argument("--check", action="store_true", help="fail if regeneration is needed")
    generator.set_defaults(run=generate)
    collector = commands.add_parser("collect")
    collector.add_argument("--suite", required=True)
    collector.add_argument("--log", type=Path, default=Path("tests/test-suite.log"))
    collector.set_defaults(run=collect)
    renderer = commands.add_parser("render")
    renderer.set_defaults(run=render)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
