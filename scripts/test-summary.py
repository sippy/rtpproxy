#!/usr/bin/env python3
"""Collect test artifacts and summarize every configured OS/compiler pair."""

import argparse
import html
import json
import os
from pathlib import Path
import re

from ci_matrix import DEFAULT_CONFIG, load_matrices


COUNTS = ('TOTAL', 'PASS', 'SKIP', 'FAIL')
SUITES = {'functional': ('FuncTest', 'Functional Testing'),
          'glitching': ('Glitching', 'Glitch Injection')}


def collect(args):
    result = {
        'suite': args.suite,
        'os': os.environ.get('GHA_OS', 'unknown'),
        'compiler': os.environ.get('COMPILER', 'unknown'),
        'run_attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')),
        'outcome': os.environ.get('TEST_OUTCOME', 'unknown'),
        'counts': {},
        'failures': [],
    }
    # A build/setup failure may skip tests and leave a stale suite log.
    if result['outcome'] in ('success', 'failure') and args.log.is_file():
        for line in args.log.read_text().splitlines():
            match = re.fullmatch(r'(TOTAL|PASS|SKIP|FAIL):\s+(\d+)', line)
            if match:
                result['counts'][match[1]] = int(match[2])
            elif line.startswith('FAIL: '):
                result['failures'].append(line)
    if set(result['counts']) != set(COUNTS):
        result['counts'] = {}
    encoded = json.dumps(result, separators=(',', ':'))
    if args.output is not None:
        args.output.write_text(encoded + '\n')
    else:
        print(encoded)


def summary_rows(matrices, needs, pages, reports):
    if isinstance(pages, dict):
        pages = [pages]
    jobs = {}
    for page in pages:
        for job in page['jobs']:
            previous = jobs.get(job['name'])
            if previous is None or (job.get('run_attempt', 0), job['id']) > (
                    previous.get('run_attempt', 0), previous['id']):
                jobs[job['name']] = job
    artifacts = {(r['suite'], r['os'], r['compiler'], r['run_attempt']): r for r in reports}
    rows = []
    for suite, (job_id, job_name) in SUITES.items():
        if needs.get(job_id, {}).get('result') == 'skipped':
            continue
        for pair in matrices[job_id]['include']:
            os_name, compiler = 'ubuntu-' + pair['os'], pair['compiler']
            job = jobs.get(f"{job_name} ({pair['os']}, {compiler})")
            row = dict(suite=suite, os=os_name, compiler=compiler, counts={},
                       failures=[], outcome='unknown', job_outcome='unknown')
            if job is not None:
                steps = {step['name']: step.get('conclusion') for step in job.get('steps', [])}
                report = artifacts.get((suite, os_name, compiler, job.get('run_attempt', 1)))
                # The jobs API can return null step conclusions even for a
                # completed job. A matching attempt's artifact records the
                # actual test outcome and proves collection succeeded.
                if report is not None:
                    row.update(counts=report['counts'], failures=report['failures'],
                               outcome=report['outcome'])
                else:
                    row['outcome'] = steps.get('test') or 'unknown'
                row['job_outcome'] = job.get('conclusion') or 'unknown'
                row['reported'] = report is not None
            rows.append(row)
    return sorted(rows, key=lambda row: (row['suite'], row['os'], row['compiler']))


def cell(value):
    return html.escape(str(value)).replace('|', '&#124;').replace('\n', ' ')


def render(args):
    needs = json.loads(os.environ.get('TEST_RESULTS', '{}'))
    reports = [json.loads(path.read_text()) for path in sorted(args.results.rglob('*.json'))]
    rows = summary_rows(load_matrices(args.matrix), needs, json.loads(args.jobs.read_text()), reports)
    print('## Test results\n')
    if not rows:
        print('No test jobs were enabled.')
        return
    print('| Suite | OS | Compiler | Job result | Test result | Total | Passed | Skipped | Failed | Failed tests |')
    print('| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |')
    for row in rows:
        counts = row['counts']
        if row['job_outcome'] == 'unknown':
            outcome = 'No job result reported'
        elif row['outcome'] in ('skipped', 'cancelled'):
            outcome = 'Tests ' + row['outcome']
        elif not row['reported']:
            outcome = 'No test summary reported'
        elif not counts:
            outcome = 'No completed test suite'
        elif row['outcome'] != 'success' or counts['FAIL']:
            outcome = 'FAIL'
        else:
            outcome = 'PASS'
        job_outcome = {'success': 'PASS', 'failure': 'FAIL', 'skipped': 'SKIP',
                       'cancelled': 'CANCELLED', 'timed_out': 'TIMED OUT'}.get(
                           row['job_outcome'], row['job_outcome'].upper())
        cells = [cell(row[key]) for key in ('suite', 'os', 'compiler')]
        cells += [job_outcome, outcome] + [str(counts.get(key, '—')) for key in COUNTS]
        cells += ['<br>'.join('<code>' + cell(name) + '</code>' for name in row['failures']) or '—']
        print('| ' + ' | '.join(cells) + ' |')
    print('\nJob result includes coverage collection and upload. Missing summaries do not imply that tests passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    collector = commands.add_parser('collect')
    collector.add_argument('--suite', required=True, choices=SUITES)
    collector.add_argument('--log', type=Path, default=Path('tests/test-suite.log'))
    collector.add_argument('--output', type=Path)
    collector.set_defaults(run=collect)
    renderer = commands.add_parser('render')
    renderer.add_argument('--jobs', type=Path, required=True, help='GitHub jobs API response or paginated responses')
    renderer.add_argument('--results', type=Path, default=Path('test-results'))
    renderer.add_argument('--matrix', type=Path, default=DEFAULT_CONFIG)
    renderer.set_defaults(run=render)
    args = parser.parse_args()
    args.run(args)


if __name__ == '__main__':
    main()
