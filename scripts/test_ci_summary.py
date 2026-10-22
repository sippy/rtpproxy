#!/usr/bin/env python3
"""Regression tests for shared CI matrices and summaries of interrupted jobs."""

import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci_matrix import DEFAULT_CONFIG, load_matrices

spec = importlib.util.spec_from_file_location('test_summary', Path(__file__).with_name('test-summary.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.matrix = {job: {'include': [{'os': '24.04', 'compiler': 'clang-20'}]}
                       for job in ('FuncTest', 'Glitching')}
        self.needs = {'FuncTest': {'result': 'skipped'}, 'Glitching': {'result': 'failure'}}

    def job(self, outcome='failure', tests='failure', collected='skipped', attempt=2):
        return dict(id=119523710160 + attempt, name='Glitch Injection (24.04, clang-20)',
                    run_attempt=attempt, conclusion=outcome,
                    steps=[dict(name='test', conclusion=tests),
                           dict(name='Collect test summary', conclusion=collected)])

    def report(self, attempt=2):
        return dict(suite='glitching', os='ubuntu-24.04', compiler='clang-20',
                    run_attempt=attempt, outcome='success', failures=[],
                    counts=dict(TOTAL=3, PASS=3, SKIP=0, FAIL=0))

    def rows(self, jobs, reports=()):
        return summary.summary_rows(self.matrix, self.needs, jobs, reports)

    def render(self, jobs, reports=()):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = dict(pairs={'native': [['24.04', 'clang-20']]},
                          jobs={job: ['native'] for job in self.matrix})
            (root/'matrix.json').write_text(json.dumps(config))
            (root/'jobs.json').write_text(json.dumps(jobs))
            results = root/'results'
            results.mkdir()
            for i, report in enumerate(reports):
                (results/f'{i}.json').write_text(json.dumps(report))
            args = argparse.Namespace(matrix=root/'matrix.json', jobs=root/'jobs.json', results=results)
            output = io.StringIO()
            with patch.dict(os.environ, TEST_RESULTS=json.dumps(self.needs)), redirect_stdout(output):
                summary.render(args)
            return output.getvalue()

    def test_interrupted_job_without_outputs_remains_visible(self):
        text = self.render({'jobs': [self.job()]})
        self.assertIn('| glitching | ubuntu-24.04 | clang-20 | FAIL | No test summary reported |', text)

    def test_cancelled_job_without_artifact(self):
        text = self.render({'jobs': [self.job(outcome='cancelled', tests='cancelled')]})
        self.assertIn('| CANCELLED | Tests cancelled |', text)

    def test_coverage_failure_preserves_successful_test_counts(self):
        text = self.render({'jobs': [self.job(tests='success', collected='success')]}, [self.report()])
        self.assertIn('| FAIL | PASS | 3 | 3 | 0 | 0 |', text)

    def test_artifact_preserves_results_with_incomplete_api_steps(self):
        for tests, collected in ((None, None), (None, 'success'), ('success', None)):
            with self.subTest(tests=tests, collected=collected):
                job = self.job(outcome='success', tests=tests, collected=collected)
                text = self.render({'jobs': [job]}, [self.report()])
                self.assertIn('| PASS | PASS | 3 | 3 | 0 | 0 |', text)

    def test_artifact_preserves_test_failure_with_missing_api_steps(self):
        job = self.job(tests=None, collected=None)
        job['steps'] = []
        report = self.report()
        report.update(outcome='failure', counts=dict(TOTAL=3, PASS=2, SKIP=0, FAIL=1),
                      failures=['FAIL: memdeb/glitch_playback'])
        text = self.render({'jobs': [job]}, [report])
        self.assertIn('| FAIL | FAIL | 3 | 2 | 0 | 1 |', text)
        self.assertIn('<code>FAIL: memdeb/glitch_playback</code>', text)

    def test_missing_step_conclusions_do_not_imply_skipped_tests(self):
        text = self.render({'jobs': [self.job(outcome='success', tests=None, collected=None)]})
        self.assertIn('| PASS | No test summary reported |', text)
        self.assertNotIn('Tests skipped', text)

    def test_explicitly_skipped_tests_remain_skipped(self):
        job = self.job(tests='skipped', collected='success')
        report = self.report()
        report.update(outcome='skipped', counts={})
        for reports in ([], [report]):
            with self.subTest(reports=reports):
                text = self.render({'jobs': [job]}, reports)
                self.assertIn('| FAIL | Tests skipped |', text)

    def test_rerun_does_not_reuse_stale_artifact_or_old_job(self):
        pages = [{'jobs': [self.job()]},
                 {'jobs': [self.job(outcome='success', tests='success', collected='success', attempt=1)]}]
        row, = self.rows(pages, [self.report(attempt=1)])
        self.assertEqual(row['job_outcome'], 'failure')
        self.assertEqual(row['counts'], {})

    def test_configured_pair_without_job_is_visible(self):
        text = self.render({'jobs': []})
        self.assertIn('| glitching | ubuntu-24.04 | clang-20 | UNKNOWN | No job result reported |', text)
        self.assertNotIn('| functional |', text)

    def test_missing_artifact_does_not_turn_successful_job_into_test_pass(self):
        text = self.render({'jobs': [self.job(outcome='success', tests='success', collected='success')]})
        self.assertIn('| PASS | No test summary reported |', text)

    def test_collect_complete_and_partial_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            log, output = Path(temp)/'suite.log', Path(temp)/'result.json'
            args = argparse.Namespace(log=log, output=output, suite='glitching')
            log.write_text('FAIL: memdeb/glitch_playback\nTOTAL: 3\nPASS: 2\nSKIP: 0\nFAIL: 1\n')
            with patch.dict(os.environ, TEST_OUTCOME='failure', GITHUB_RUN_ATTEMPT='2'):
                summary.collect(args)
            report = json.loads(output.read_text())
            self.assertEqual(report['counts'], dict(TOTAL=3, PASS=2, SKIP=0, FAIL=1))
            self.assertEqual(report['failures'], ['FAIL: memdeb/glitch_playback'])
            self.assertEqual(report['run_attempt'], 2)
            log.write_text('TOTAL: 3\nPASS: 2\n')
            with patch.dict(os.environ, TEST_OUTCOME='failure'):
                summary.collect(args)
            self.assertEqual(json.loads(output.read_text())['counts'], {})
            with patch.dict(os.environ, TEST_OUTCOME='skipped'):
                summary.collect(args)
            self.assertEqual(json.loads(output.read_text())['counts'], {})


class MatrixTests(unittest.TestCase):
    def test_new_native_pair_propagates_to_each_job(self):
        config = json.loads(DEFAULT_CONFIG.read_text())
        config['pairs']['native'].append(['future-os', 'future-compiler'])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'matrix.json'
            path.write_text(json.dumps(config))
            matrices = load_matrices(path)
        for job, groups in config['jobs'].items():
            if 'native' in groups:
                self.assertIn(dict(os='future-os', compiler='future-compiler'), matrices[job]['include'])
        cross = dict(zip(('os', 'compiler'), config['pairs']['cross'][0]))
        self.assertIn(cross, matrices['MinBuild']['include'])
        self.assertNotIn(cross, matrices['FullBuild']['include'])

    def test_duplicate_pairs_are_rejected(self):
        config = json.loads(DEFAULT_CONFIG.read_text())
        config['pairs']['native'].append(config['pairs']['native'][0])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'matrix.json'
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, 'duplicate OS/compiler pair'):
                load_matrices(path)


if __name__ == '__main__':
    unittest.main()
