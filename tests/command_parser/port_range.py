#!/usr/bin/env python3
"""Lease a four-port RTP range while running a command-parser test."""

import fcntl
import os
import socket
import sys
import tempfile


def main(argv):
    # Record locks survive exec and are released when the test shell exits.
    path = os.path.join(tempfile.gettempdir(),
      f'rtpproxy-command-parser.{os.getuid()}.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    for base in range(10000, 30000, 4):
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 4, base)
        except BlockingIOError:
            continue
        sockets = []
        try:
            for port in range(base, base + 4):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                sock.bind(('0.0.0.0', port))
        except OSError:
            fcntl.lockf(fd, fcntl.LOCK_UN, 4, base)
            continue
        finally:
            for sock in sockets:
                sock.close()
        os.environ['RTPP_CP_PORT_MIN'] = str(base)
        os.environ['RTPP_CP_PORT_MAX'] = str(base + 3)
        os.set_inheritable(fd, True)
        os.execv(argv[0], argv)
    raise RuntimeError('no free four-port command-parser range')


if __name__ == '__main__':
    main(sys.argv[1:])
