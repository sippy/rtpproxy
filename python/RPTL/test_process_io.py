"""Check concurrent managed output and reaping without per-child threads."""

import shlex
import signal
import sys
import os
from pathlib import Path
from subprocess import Popen, DEVNULL, run
import tempfile
import threading
import unittest
from unittest.mock import patch

from rptl_run import ManagedProcess, ManagedRtpProxy, StdioRtpProxyClient
from sippy.Core.EventDispatcher import ED2


class ProcessIOTests(unittest.TestCase):
    def setUp(self):
        # Deliver callbacks directly so these tests need no running ED2 loop.
        callbacks = patch.object(ED2, 'callFromThread',
          side_effect=lambda callback, *args: callback(*args))
        callbacks.start()
        self.addCleanup(callbacks.stop)

    def start_child(self, code):
        process = ManagedProcess('test',
          'exec ' + shlex.join([sys.executable, '-c', code]))
        self.addCleanup(process.stop)
        return process

    def completed(self, process, timeout=5):
        self.assertTrue(process._done.wait(timeout), 'child failed to complete')

    def test_many_children_share_one_reader(self):
        children = [self.start_child('import time; time.sleep(60)')
          for _ in range(35)]
        readers = [thread for thread in threading.enumerate()
          if thread.name == 'rptl-process-io']
        self.assertEqual(len(readers), 1)
        # All child supervision is done by that one reader thread.
        self.assertEqual(threading.active_count(), 2)
        for child in children:
            child.signal(signal.SIGTERM)
        for child in children:
            self.completed(child)
            self.assertEqual(child.rc, -signal.SIGTERM)

    def test_fragmented_output_and_final_line(self):
        child = self.start_child('''import os, time
os.write(1, b'first\\r\\n\\n' + b'x' * 70000 + b'\\n\\xe2')
time.sleep(0.1)
os.write(1, b'\\x82\\xac\\ninvalid: \\xff\\nlast')
''')
        self.completed(child)
        self.assertEqual(child.rc, 0)
        self.assertEqual(list(child.lines),
          ['first', '', 'x' * 70000, '\u20ac', 'invalid: \ufffd', 'last'])

    def test_stdout_eof_does_not_block_other_children(self):
        slow = self.start_child('import os, time; os.close(1); time.sleep(60)')
        quick = self.start_child('print("ready")')
        self.completed(quick)
        self.assertEqual(list(quick.lines), ['ready'])
        self.assertFalse(slow._done.is_set())
        slow.signal(signal.SIGKILL)
        self.completed(slow)
        self.assertEqual(slow.rc, -signal.SIGKILL)

    def test_exit_is_delivered_after_queued_output(self):
        callbacks = []
        updates = []
        with patch.object(ED2, 'callFromThread',
          side_effect = lambda callback, *args: callbacks.append((callback, args))):
            child = self.start_child('print("ready")')
            child.on_update = lambda: updates.append((child.rc, list(child.lines)))
            self.completed(child)
            self.assertEqual(child.wait(), 0)
            self.assertIsNone(child.rc)
            for callback, args in callbacks:
                callback(*args)
        self.assertEqual(updates, [(None, ['ready']), (0, ['ready'])])


class RtpProxyExitTests(unittest.TestCase):
    def child(self, code):
        proc = Popen([sys.executable, '-c', code], stdout = DEVNULL,
          stderr = DEVNULL)
        self.addCleanup(self.reap, proc)
        return proc

    @staticmethod
    def reap(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    def client(self, cls, proc):
        client = cls.__new__(cls)
        client.proc = proc
        client.process = ManagedProcess.from_proc('exit-test', proc)
        client.instance_name = 'exit-test'
        client._stderr = None
        client._stdio_sock = None
        return client

    def test_shutdown_records_crashes_and_normal_failures(self):
        for cls in (StdioRtpProxyClient, ManagedRtpProxy):
            for rc in (-signal.SIGSEGV, 1):
                with self.subTest(client = cls.__name__, rc = rc), \
                  tempfile.TemporaryDirectory() as directory:
                    status = Path(directory) / 'status'
                    code = ('import os, resource, signal; '
                      'resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); '
                      'os.kill(os.getpid(), signal.SIGSEGV)' if rc < 0 else
                      'raise SystemExit(1)')
                    proc = self.child(code)
                    self.assertEqual(proc.wait(timeout = 5), rc)
                    with patch.dict(os.environ,
                      RPTL_EXIT_STATUS = str(status)):
                        client = self.client(cls, proc)
                        with self.assertRaises(RuntimeError):
                            client.shutdown(abandon = True)
                    self.assertEqual(status.read_text(), f'{proc.pid} {rc} 0\n')
                    self.assertIsNone(client.proc)

    def test_cleanup_records_deliberate_kill(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / 'status'
            proc = self.child('import time; time.sleep(60)')
            client = self.client(ManagedRtpProxy, proc)
            with patch.dict(os.environ, RPTL_EXIT_STATUS = str(status)):
                client._cleanup()
            self.assertEqual(status.read_text(),
              f'{proc.pid} {-signal.SIGKILL} {int(signal.SIGKILL)}\n')
            self.assertIsNone(client.proc)


class ManagedInstanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix = 'rptl-instance-test.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proxy = self.root / 'proxy'
        self.proxy.write_text(f'#!{sys.executable}\n' + '''import os, resource, signal, time
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
mode = os.environ['PROXY_TEST_MODE']
if mode == 'crash':
    os.kill(os.getpid(), signal.SIGSEGV)
elif mode == 'fail':
    raise SystemExit(7)
else:
    time.sleep(60)
''')
        self.proxy.chmod(0o755)

    def script(self, transport, commands, mode = 'wait'):
        script = self.root / 'test.rptl'
        script.write_text(f'socket rtpp: {transport}:\n' + commands)
        status = self.root / 'status'
        status.unlink(missing_ok = True)
        result = run([sys.executable,
          str(Path(__file__).with_name('rptl_run.py').resolve()),
          '-s', str(script), '-D', f'RTPPROXY_BIN={self.proxy}'],
          cwd = self.root, env = dict(os.environ,
            PROXY_TEST_MODE = mode, RPTL_EXIT_STATUS = str(status)),
          text = True, capture_output = True, timeout = 20)
        statuses = [list(map(int, line.split()))
          for line in status.read_text().splitlines()]
        return result, statuses

    def test_kill_wait_and_reuse_instance_name(self):
        for transport in ('stdio', 'udp'):
            with self.subTest(transport = transport):
                result, statuses = self.script(transport, '''.kill: rtpp TERM
.wait: rtpp 5 -> RC
.spawn: exec true -> rtpp
.wait: rtpp 5
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("'RC': '-15'", result.stdout)
                self.assertEqual(len(statuses), 2)
                self.assertEqual(statuses[0][1:], [-signal.SIGTERM, signal.SIGTERM])
                self.assertEqual(statuses[1][1:], [0, 0])

    def test_wait_validates_or_captures_instance_exit(self):
        for transport in ('stdio', 'udp'):
            for mode, rc in (('crash', -signal.SIGSEGV), ('fail', 7)):
                for capture in (False, True):
                    with self.subTest(transport = transport, mode = mode,
                      capture = capture):
                        command = '.wait: rtpp 5' + (' -> RC' if capture else '')
                        result, statuses = self.script(transport, command, mode)
                        self.assertEqual(result.returncode == 0, capture, result.stderr)
                        self.assertEqual(statuses[0][1:], [rc, 0])
                        if capture:
                            self.assertIn(f"'RC': '{rc}'", result.stdout)

    def test_crash_is_recorded_when_command_fails_before_wait(self):
        for transport in ('stdio', 'udp'):
            with self.subTest(transport = transport):
                result, statuses = self.script(transport,
                  'rtpp: V\n.wait: rtpp 5\n', 'crash')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(statuses[0][1:], [-signal.SIGSEGV, 0])


if __name__ == '__main__':
    unittest.main()
