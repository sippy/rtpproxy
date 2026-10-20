#!/usr/bin/env python3
"""Exercise the Python-helper lifecycle through the RPTL CLI."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PythonSpawnTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rptl-pyspawn-test.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.child = self.root / 'child helper.py'
        self.child.write_text('''import os, signal, sys, time
mode = sys.argv[1]
if mode == 'echo':
    print(' '.join(sys.argv[2:]), flush=True)
elif mode == 'environment':
    print(os.getcwd() + '|' + os.environ['PYSPAWN_TEST_VALUE'], flush=True)
    assert sys.stdin.read() == ''
elif mode == 'fail':
    sys.exit(7)
elif mode == 'wait':
    print(os.getpid(), flush=True)
    while True:
        time.sleep(1)
elif mode == 'cleanup':
    with open(sys.argv[2], 'w') as f:
        f.write(str(os.getpid()))
    print('READY', flush=True)
    while True:
        time.sleep(1)
''')

    def run_script(self, script, baseline=False):
        path = self.root / 'test.rptl'
        path.write_text(script)
        env = dict(os.environ, RPTL_PYSPAWN='0' if baseline else '1',
          PYSPAWN_TEST_VALUE='inherited value')
        return subprocess.run([sys.executable,
          str(Path(__file__).with_name('rptl_run.py')), '-s', str(path),
          '-D', 'CHILD=' + str(self.child)], cwd=self.root, env=env,
          text=True, capture_output=True, timeout=20)

    def test_output_arguments_and_environment(self):
        # Start an output-reader thread before the first Python helper.
        script = f''' .spawn: exec sleep 0.1 -> OTHER
.eval: hello spaced argument -> EXPECTED
.pyspawn: "%%CHILD%%" echo hello "spaced argument" -> PROC
.readline: PROC 10 -> str_compare(EXPECTED)
.wait: PROC 10
.eval: {self.root}|inherited value -> EXPECTED
.pyspawn: "%%CHILD%%" environment -> ENV
.readline: ENV 10 -> str_compare(EXPECTED)
.wait: ENV 10
.wait: OTHER 10
'''
        for baseline in (False, True):
            with self.subTest(baseline=baseline):
                result = self.run_script(script, baseline)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_exit_status(self):
        result = self.run_script('''.eval: 7 -> EXPECTED
.pyspawn: "%%CHILD%%" fail -> PROC
.wait: PROC 10 -> str_compare(EXPECTED)
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script('''.pyspawn: "%%CHILD%%" fail -> PROC
.wait: PROC 10
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exited with return code 7', result.stderr)

    def test_signal_and_process_group(self):
        result = self.run_script('''.eval: -15 -> EXPECTED
.pyspawn: "%%CHILD%%" wait -> PROC
.readline: PROC 10 -> CHILD_PID
.eval: %%PROC%% -> str_compare(CHILD_PID)
.kill: PROC
.wait: PROC 10 -> str_compare(EXPECTED)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleanup_after_script_failure(self):
        pidfile = self.root / 'pid'
        result = self.run_script(f'''.eval: READY -> EXPECTED
.pyspawn: "%%CHILD%%" cleanup "{pidfile}" -> PROC
.readline: PROC 10 -> str_compare(EXPECTED)
.exec: false
''')
        self.assertNotEqual(result.returncode, 0)
        pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


if __name__ == '__main__':
    unittest.main()
