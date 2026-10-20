#!/usr/bin/env python3
"""Reserve startstop listeners and pass them through every daemon run."""

from contextlib import ExitStack
import os
import socket
import sys


def main(argv):
    listeners = (
      ('udp', socket.AF_INET, socket.SOCK_DGRAM, '127.0.0.1'),
      ('tcp', socket.AF_INET, socket.SOCK_STREAM, '127.0.0.1'),
      ('udp6', socket.AF_INET6, socket.SOCK_DGRAM, '::1'),
      ('tcp6', socket.AF_INET6, socket.SOCK_STREAM, '::1'))
    args = []
    with ExitStack() as stack:
        for name, family, kind, host in listeners:
            sock = stack.enter_context(socket.socket(family, kind))
            sock.bind((host, 0))
            if kind == socket.SOCK_STREAM:
                sock.listen(32)
            sock.set_inheritable(True)
            args.extend(('-s', f'fd:{sock.fileno()}'))
            print(f'OK: allocated startstop {name} listener on '
              f'{host}:{sock.getsockname()[1]}', file=sys.stderr, flush=True)
        os.environ['STARTSTOP_CONTROL_ARGS'] = ' '.join(args)
        os.execv(argv[0], argv)


if __name__ == '__main__':
    main(sys.argv[1:])
