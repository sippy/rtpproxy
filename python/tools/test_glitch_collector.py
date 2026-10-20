#!/usr/bin/env python3
"""Exercise the shared glitch collector's connection and daemon lifecycle."""

import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


CLIENT = Path(__file__).with_name('rtpp_notify_client.py')


class GlitchCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='glitch-collector-test.')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'hits'

    def wait_for_reports(self, count):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            lines = self.output.read_text().splitlines()
            if len(lines) >= count:
                return lines
            time.sleep(0.01)
        self.fail(f'expected {count} reports, received {len(lines)}')

    def test_many_connections_and_fragmented_reports_without_threads(self):
        # Fail deterministically if collection starts even one Python thread.
        bootstrap = '''import os, runpy, sys, threading
def no_threads(*args, **kwargs):
    raise RuntimeError('collector started a thread')
threading.Thread.start = no_threads
sys.argv = sys.argv[1:]
sys.path.insert(0, os.path.dirname(sys.argv[0]))
runpy.run_path(sys.argv[0], run_name='__main__')
'''
        proc = subprocess.Popen([sys.executable, '-c', bootstrap, str(CLIENT),
          '-G', '-P', '-s', 'tcp:127.0.0.1:0', '-o', str(self.output), '-t', '30'],
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        peers = []
        try:
            self.assertTrue(select.select([proc.stdout], [], [], 10)[0])
            line = proc.stdout.readline()
            if not line:
                self.fail(proc.stderr.read())
            port = int(line)
            expected = set()
            for number in range(800):
                peer = socket.create_connection(('127.0.0.1', port), timeout=10)
                peers.append(peer)
                line = f's0: c{number:04X} called from test() at fixture:1'
                peer.sendall((line + f'\ns0: c{number:04X} called ').encode())
                # Keep all peers open, but avoid overflowing the kernel's
                # pending-accept backlog while the collector is scheduled.
                if (number + 1) % 32 == 0:
                    self.wait_for_reports(number + 1)
            for number, peer in enumerate(peers):
                line = f's0: c{number:04X} called from test() at fixture:1'
                expected.add(line)
                peer.sendall(b'from test() at fixture:1\n')
            lines = self.wait_for_reports(1600)
            self.assertEqual(len(lines), 1600)
            self.assertEqual(set(lines), expected)
            for peer in peers:
                peer.close()
            proc.terminate()
            _, errors = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, errors)
            self.assertEqual(errors, '')
        finally:
            for peer in peers:
                peer.close()
            if proc.poll() is None:
                proc.kill()
            proc.communicate()

    def test_daemon_reports_pid_port_and_exits_on_term(self):
        log = Path(self.temp.name) / 'daemon.log'
        result = subprocess.run([sys.executable, str(CLIENT), '-G', '-D',
          '-s', 'tcp:127.0.0.1:0', '-o', str(self.output), '-l', str(log)],
          capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        pid, port = map(int, result.stdout.split())
        stopped = False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=5) as peer:
                peer.sendall(b's0: c0001 called from test() at fixture:1\n')
            self.assertEqual(len(self.wait_for_reports(1)), 1)
            os.kill(pid, signal.SIGTERM)
            # The daemon is reparented; observe its listening socket close.
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        pass
                except OSError:
                    stopped = True
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            self.assertEqual(log.read_text(), '')
        finally:
            if not stopped:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def test_normal_notification_mode(self):
        proc = subprocess.Popen([sys.executable, str(CLIENT), '-P',
          '-s', 'tcp:127.0.0.1:0', '-o', str(self.output), '-t', '10'],
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([proc.stdout], [], [], 10)[0])
            line = proc.stdout.readline()
            if not line:
                self.fail(proc.stderr.read())
            with socket.create_connection(('127.0.0.1', int(line)), timeout=5) as peer:
                peer.sendall(b'notification-tag\n')
            self.assertEqual(self.wait_for_reports(1), ['notification-tag'])
            proc.terminate()
            _, errors = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, errors)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()


if __name__ == '__main__':
    unittest.main()
