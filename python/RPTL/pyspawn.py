# Python helpers forked from a dedicated, single-threaded interpreter. The
# RPTL process itself may already have control and shared I/O threads.

import multiprocessing
import os
import runpy
import signal
import sys
from subprocess import TimeoutExpired

# Generous enough for the fork server to come up under parallel glitching.
READY_TIMEOUT = 30


def _run_script(argv, cwd, environ, output, ready):
    try:
        os.setsid()
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_DFL)
        with open(os.devnull, 'rb') as source:
            os.dup2(source.fileno(), 0)
        os.dup2(output.fileno(), 1)
        output.close()
        sys.stdin = open(0, 'r', closefd=False)
        sys.stdout = open(1, 'w', buffering=1, closefd=False)
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(environ)
        sys.argv = argv
        sys.path.insert(0, os.path.dirname(os.path.abspath(argv[0])))
        # A spawn is ready only after its process group and stdout exist.
        ready.send(True)
        ready.close()
        runpy.run_path(argv[0], run_name='__main__')
    finally:
        ready.close()
        sys.stdout.flush()


class PythonProcess:
    """The Popen subset used by RPTL's managed-process lifecycle."""

    def __init__(self, argv):
        if not argv:
            raise ValueError('.pyspawn requires a script path')
        ctx = multiprocessing.get_context('forkserver')
        output_read, output_write = ctx.Pipe(duplex=False)
        ready_read, ready_write = ctx.Pipe(duplex=False)
        self.proc = ctx.Process(target=_run_script,
          args=(argv, os.getcwd(), dict(os.environ), output_write, ready_write))
        self.stdout = None
        self._returncode = None
        try:
            self.proc.start()
            output_write.close()
            ready_write.close()
            if not ready_read.poll(READY_TIMEOUT):
                raise TimeoutError('Python helper did not initialize within '
                  f'{READY_TIMEOUT} seconds')
            ready_read.recv()
            self.stdout = os.fdopen(os.dup(output_read.fileno()), 'rb')
        except BaseException:
            if self.proc.pid is not None:
                if self.proc.is_alive():
                    self.proc.terminate()
                self.proc.join(2)
                if self.proc.is_alive():
                    self.proc.kill()
                    self.proc.join()
            raise
        finally:
            output_read.close()
            output_write.close()
            ready_read.close()
            ready_write.close()
        self.pid = self.proc.pid

    @property
    def returncode(self):
        # Only the shared I/O thread reaps the process. Concurrent polls
        # would race with join() on multiprocessing's fork-server status pipe.
        return self._returncode

    def wait(self, timeout=None):
        self.proc.join(timeout)
        if self.proc.is_alive():
            raise TimeoutExpired(self.proc.name, timeout)
        self._returncode = self.proc.exitcode
        return self._returncode
