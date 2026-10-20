#!/usr/bin/env python3
# Receive HEP over TCP or UDP on an ephemeral loopback port. Print the
# port when ready, save all payloads, then print their total size on EOF
# (TCP) or SIGTERM (UDP). Drain queued data before exiting on SIGTERM.

import signal
import socket
import sys


class Done(Exception):
    pass


def done(*args):
    raise Done()


def main(proto, outfile):
    stype = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, stype) as listener, open(outfile, 'wb') as out:
        listener.bind(('127.0.0.1', 0))
        if proto == 'tcp':
            listener.listen(1)
        signal.signal(signal.SIGTERM, done)
        signal.signal(signal.SIGINT, done)
        conn = None
        nbytes = 0
        try:
            print(listener.getsockname()[1], flush=True)
            conn = listener.accept()[0] if proto == 'tcp' else listener
            while True:
                data = conn.recv(65536)
                if not data and proto == 'tcp':
                    break
                out.write(data)
                nbytes += len(data)
        except Done:
            pass
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if conn is not None:
            conn.setblocking(False)
            while True:
                try:
                    data = conn.recv(65536)
                except BlockingIOError:
                    break
                if not data and proto == 'tcp':
                    break
                out.write(data)
                nbytes += len(data)
            if conn is not listener:
                conn.close()
    print(nbytes, flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('tcp', 'udp'):
        sys.exit('usage: hep_sink.py tcp|udp outfile')
    main(*sys.argv[1:])
