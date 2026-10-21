#!/usr/bin/env python3
"""Exercise stream destruction while the playback thread holds references."""

import selectors
import socket
import subprocess
import sys


def run(prompt, logfile, command):
    with open(logfile, 'w+') as errors, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as caller, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as callee:
        caller.bind(('127.0.0.1', 0))
        callee.bind(('127.0.0.1', 0))
        caller_port = caller.getsockname()[1]
        callee_port = callee.getsockname()[1]
        with subprocess.Popen(
            command + ['-f', '-s', 'stdio:', '-l', '127.0.0.1', '-b',
                       '-d', 'err', '-T', '300', '-p', logfile + '.pid'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
            text=True,
        ) as proxy, selectors.DefaultSelector() as reader:
            reader.register(proxy.stdout, selectors.EVENT_READ)

            def issue(line):
                proxy.stdin.write(line + '\n')
                proxy.stdin.flush()
                if not reader.select(10):
                    raise TimeoutError(f'no reply to {line!r}')
                reply = proxy.stdout.readline().strip()
                if not reply or reply.startswith('E'):
                    raise RuntimeError(f'{line!r}: {reply!r}')

            try:
                for batch in range(100):
                    for i in range(20):
                        cid = f'delete-active-{batch}-{i}'
                        issue(f'U {cid} 127.0.0.1 {caller_port} from')
                        issue(f'L {cid} 127.0.0.1 {callee_port} from to')
                        issue(f'P {cid} {prompt} 0 from')
                    for i in range(20):
                        issue(f'D delete-active-{batch}-{i} from')
                proxy.stdin.close()
                rc = proxy.wait(timeout=10)
                if rc != 0:
                    raise RuntimeError(f'proxy exited with status {rc}')
            finally:
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.wait()
                errors.seek(0)
                sys.stderr.write(errors.read())


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2], sys.argv[3:])
