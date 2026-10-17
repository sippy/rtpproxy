#!/usr/bin/env python3
#
# Binds a UDP socket to an ephemeral port on the given address, prints the
# port number, then receives datagrams (optionally saving payloads into a
# file) until SIGTERM/SIGINT, at which point prints the total number of
# bytes received and exits.
#

import sys, signal, socket

class Done(Exception):
    pass

def done(*args):
    raise Done()

def main():
    if len(sys.argv) not in (2, 3):
        sys.stderr.write('usage: udp_sink.py address [outfile]\n')
        sys.exit(2)
    host = sys.argv[1]
    outf = open(sys.argv[2], 'wb') if len(sys.argv) == 3 else None
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, 0))
    signal.signal(signal.SIGTERM, done)
    signal.signal(signal.SIGINT, done)
    nbytes = 0
    try:
        print(s.getsockname()[1], flush = True)
        while True:
            data = s.recv(65536)
            nbytes += len(data)
            if outf is not None:
                outf.write(data)
    except Done:
        pass
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # Drain whatever is left queued in the socket buffer
    s.setblocking(False)
    while True:
        try:
            data = s.recv(65536)
        except BlockingIOError:
            break
        nbytes += len(data)
        if outf is not None:
            outf.write(data)
    if outf is not None:
        outf.close()
    print(nbytes, flush = True)

if __name__ == '__main__':
    main()
