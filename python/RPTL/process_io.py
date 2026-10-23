"""Multiplex managed-process stdout and exit notifications on one thread."""

import os
from queue import SimpleQueue, Empty
from selectors import DefaultSelector, EVENT_READ
from socket import socketpair
from subprocess import TimeoutExpired
from threading import Event, Thread


class ProcessIO:
    def __init__(self):
        self.selector = DefaultSelector()
        self.wakeup_read, self.wakeup_write = socketpair()
        self.wakeup_read.setblocking(False)
        self.wakeup_write.setblocking(False)
        self.selector.register(self.wakeup_read, EVENT_READ, None)
        self.incoming = SimpleQueue()
        self.pending_exit = []
        self.thread = Thread(target=self._run, name='rptl-process-io', daemon=True)
        self.thread.start()

    def register(self, process):
        done = Event()
        self.incoming.put((process, done))
        try:
            self.wakeup_write.send(b'\0')
        except BlockingIOError:
            # A queued wakeup already makes the selector readable.
            pass
        return done

    def _register_pending(self):
        while True:
            try:
                self.wakeup_read.recv(4096)
            except BlockingIOError:
                break
        while True:
            try:
                process, done = self.incoming.get_nowait()
            except Empty:
                break
            if process.proc.stdout is None:
                # Native managed clients own their sockets and log streams.
                self.pending_exit.append((process, done))
                continue
            os.set_blocking(process.proc.stdout.fileno(), False)
            self.selector.register(process.proc.stdout, EVENT_READ,
              (process, done, bytearray()))

    def _read_output(self, key):
        from sippy.Core.EventDispatcher import ED2
        process, done, buffer = key.data
        try:
            data = os.read(key.fd, 65536)
        except BlockingIOError:
            return
        buffer.extend(data)
        lines = buffer.split(b'\n')
        buffer[:] = lines.pop()
        for line in lines:
            ED2.callFromThread(process._got_line,
              line.decode(errors='replace').rstrip('\r\n'))
        if data:
            return
        if buffer:
            ED2.callFromThread(process._got_line,
              buffer.decode(errors='replace').rstrip('\r\n'))
        self.selector.unregister(key.fileobj)
        key.fileobj.close()
        self.pending_exit.append((process, done))

    def _run(self):
        while True:
            # EOF can precede exit (a helper may close stdout and keep running).
            # Never block the other helpers while waiting to reap that process.
            timeout = 0.01 if self.pending_exit else None
            for key, _ in self.selector.select(timeout):
                if key.data is None:
                    self._register_pending()
                else:
                    self._read_output(key)
            pending = self.pending_exit
            self.pending_exit = []
            for process, done in pending:
                try:
                    rc = process.proc.wait(timeout=0)
                except TimeoutExpired:
                    self.pending_exit.append((process, done))
                    continue
                process._got_exit(rc)
                done.set()


# Imported lazily by ManagedProcess after the first child has started.
process_io = ProcessIO()
