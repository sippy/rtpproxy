#!/usr/bin/env python3
"""Trace host signals and log resources while running a CI test command."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event, Thread


@contextmanager
def trace_signals():
    ready = Event()
    checked = Event()
    probe_pid = None
    script = Path(__file__).with_name('ci-signals.bt')
    tracer = subprocess.Popen(
        ['sudo', '-n', '--', 'bpftrace', '-q', '-B', 'line',
         '-p', str(os.getpid()), str(script)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )

    def read_trace():
        for line in tracer.stdout:
            timestamp = datetime.now(timezone.utc).isoformat()
            print(f'CI signal: {timestamp} {line.rstrip()}', flush=True)
            if line.strip() == 'READY':
                ready.set()
            if (probe_pid is not None and line.startswith('sig=15 ')
                    and f'target_tid={probe_pid} ' in line):
                checked.set()
        # Also wake startup if bpftrace exits before attaching.
        ready.set()

    reader = Thread(target=read_trace, daemon=True)
    reader.start()
    try:
        if not ready.wait(30) or tracer.poll() is not None:
            raise RuntimeError('CI signal tracer failed to start')
        with subprocess.Popen(['sleep', '30']) as probe:
            probe_pid = probe.pid
            probe.terminate()
            probe.wait(timeout=5)
        if not checked.wait(10):
            raise RuntimeError('CI signal tracer did not observe the SIGTERM probe')
        print('CI signal: SIGTERM probe passed; starting tests', flush=True)
        # -p makes bpftrace exit if this monitor dies, including on shutdown.
        yield
        if tracer.poll() is not None:
            raise RuntimeError('CI signal tracer exited during the tests')
    finally:
        if tracer.poll() is None:
            # sudo forwards SIGINT to bpftrace. Use sudo to signal its root PID.
            subprocess.run(['sudo', '-n', '--', 'kill', '-INT', str(tracer.pid)],
                           check=False, timeout=5)
            try:
                tracer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                subprocess.run(['sudo', '-n', '--', 'kill', '-TERM', str(tracer.pid)],
                               check=False, timeout=5)
                tracer.wait(timeout=10)
        reader.join(timeout=5)
        tracer.stdout.close()


def sample():
    metrics = {'time': datetime.now(timezone.utc).isoformat(), 'cpus': os.cpu_count()}
    try:
        memory = dict(line.split(':', 1)
                      for line in Path('/proc/meminfo').read_text().splitlines())
        metrics['memory_kib'] = {
            key: int(memory[key].split()[0])
            for key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')
        }
        metrics['load'] = Path('/proc/loadavg').read_text().strip()
        vmstat = dict(line.split() for line in Path('/proc/vmstat').read_text().splitlines())
        metrics['host_oom_kills'] = int(vmstat['oom_kill'])
    except (OSError, KeyError, ValueError) as error:
        metrics['host_error'] = str(error)
    try:
        result = subprocess.run(
            ['docker', 'stats', '--no-stream', '--format', '{{json .}}',
             'rtpproxy-tests'], capture_output=True, text=True, timeout=5,
            check=True,
        )
        metrics['container'] = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        metrics['container_error'] = str(error)
    print('CI resources: ' + json.dumps(metrics), flush=True)


def run(command):
    done = Event()

    def monitor():
        while True:
            sample()
            if done.wait(10):
                return

    with subprocess.Popen(command) as test:
        thread = Thread(target=monitor, daemon=True)
        thread.start()
        try:
            rc = test.wait()
        finally:
            done.set()
            thread.join(timeout=6)
    return rc if rc >= 0 else 128 - rc


if __name__ == '__main__':
    with trace_signals():
        result = run(sys.argv[1:])
    sys.exit(result)
