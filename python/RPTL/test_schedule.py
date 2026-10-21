#!/usr/bin/env python3
"""Exercise scheduled blocks through the RPTL CLI and a real UDP peer."""

from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from threading import Event, Thread
import unittest


class ScheduleTests(unittest.TestCase):
    def run_script(self, main, files, replies=('0', '1', '2')):
        with tempfile.TemporaryDirectory(prefix='rptl-schedule.') as temp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(0.1)
            stopped = Event()
            queries = []

            def serve():
                while not stopped.is_set():
                    try:
                        data, addr = server.recvfrom(4096)
                    except socket.timeout:
                        continue
                    cookie, query = data.decode().split(' ', 1)
                    queries.append(query)
                    reply = replies[min(len(queries) - 1, len(replies) - 1)]
                    if reply is not None:
                        server.sendto(f'{cookie} {reply}'.encode(), addr)

            thread = Thread(target=serve)
            thread.start()
            try:
                script = Path(temp) / 'test.rptl'
                script.write_text(
                    f'socket q: udp:127.0.0.1:{server.getsockname()[1]}\n' + main)
                for name, body in files.items():
                    (Path(temp) / name).write_text(body)
                result = subprocess.run(
                    [sys.executable, str(Path(__file__).with_name('rptl_run.py')),
                     '-s', str(script)], capture_output=True, text=True, timeout=10)
            finally:
                stopped.set()
                thread.join(timeout=2)
        return result, queries

    def test_shared_state_include_and_foreach(self):
        result, queries = self.run_script('''.eval: 2 -> EXPECTED
.eval: start -> HISTORY
.until: DONE do check.rptl every 0.01 3
.echo: history=%%HISTORY%% count=%%COUNT%%
''', {'check.rptl': '''.foreach: ITEM in a b do append.rptl
.include: query.rptl
.eval: %%COUNT%% -> str_equal(EXPECTED, DONE)
''', 'append.rptl': '.eval: %%HISTORY%%%%ITEM%% -> HISTORY\n',
      'query.rptl': 'q: Qv call from to npkts_ina -> COUNT\n'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(queries, ['Qv call from to npkts_ina'] * 3)
        self.assertIn('history=startababab count=2', result.stderr)

    def test_timeout_during_delay(self):
        result, queries = self.run_script('''.eval: 2 -> EXPECTED
.until: DONE do check.rptl every 1 0.2
.echo: completed
''', {'check.rptl': '''q: Qv call from to npkts_ina -> COUNT
.eval: %%COUNT%% -> str_equal(EXPECTED, DONE)
'''}, replies=('1',))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(queries), 1)
        self.assertIn('timed out after 0.2 seconds', result.stderr)
        self.assertIn("DONE='0'", result.stderr)
        self.assertNotIn('completed\n', result.stderr)

    def test_errors_are_not_retried(self):
        result, queries = self.run_script('''.eval: 2 -> EXPECTED
.until: DONE do check.rptl every 0.01 3
''', {'check.rptl': 'q: Qv call from to npkts_ina -> str_compare(EXPECTED)\n'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(queries), 1)
        self.assertIn('AssertionError', result.stderr)

    def test_nested_schedules_and_reentry(self):
        result, queries = self.run_script('''.eval: 1 -> EXPECTED
.foreach: ITEM in a b do outer.rptl
.echo: done %%ITEM%%
''', {'outer.rptl': '.until: DONE do nested.rptl every 0.01 3\n',
      'nested.rptl': '''.until: INNER_DONE do check.rptl every 0.01 2
.eval: 1 -> DONE
''', 'check.rptl': '''q: V -> COUNT
.eval: %%COUNT%% -> str_equal(EXPECTED, INNER_DONE)
'''}, replies=('0', '1'))
        self.assertEqual(result.returncode, 0, result.stderr)
        # Both schedule completion flags must be reset on the second entry.
        self.assertEqual(len(queries), 3)
        self.assertIn('done b', result.stderr)

    def test_overall_timeout_covers_pending_command(self):
        result, queries = self.run_script('''.until: DONE do check.rptl every 0.01 0.2
''', {'check.rptl': 'q: V -> COUNT\n'}, replies=(None,))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(queries), 1)
        self.assertIn('timed out after 0.2 seconds', result.stderr)
        self.assertIn("last action: 'V'", result.stderr)

    def test_outer_timeout_covers_nested_schedule(self):
        result, queries = self.run_script('''.until: DONE do outer.rptl every 0.01 0.2
''', {'outer.rptl': '.until: INNER do inner.rptl every 0.01 3\n',
      'inner.rptl': '.sleep: 1\n'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DONE do outer.rptl every', result.stderr)
        self.assertIn('timed out after 0.2 seconds', result.stderr)

    def test_rejects_invalid_durations(self):
        for duration in ('0', '-1', 'nan', 'inf'):
            with self.subTest(duration=duration):
                result, queries = self.run_script(
                    f'.until: DONE do check.rptl every {duration} 1\n',
                    {'check.rptl': '.eval: 1 -> DONE\n'})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('positive and finite', result.stderr)
                self.assertEqual(queries, [])


if __name__ == '__main__':
    unittest.main()
