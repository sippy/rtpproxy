"""Check concurrent managed output and reaping without per-child threads."""

import shlex
import signal
import sys
import threading
import unittest
from unittest.mock import patch

from rptl_run import ManagedProcess
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


if __name__ == '__main__':
    unittest.main()
