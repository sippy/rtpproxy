"""Relay a real DTLS peer and reject any server reply before authorization.

Three ClientHello flights prove the peer reached the relay and retransmitted;
a disconnected peer or a process that never starts cannot make the test pass.
SIGUSR1 opens the return path only after the runner observes this boundary.
"""
import signal
import socket
import sys
import time

host, target_port = sys.argv[1:]
family = socket.AF_INET6 if ':' in host else socket.AF_INET
authorized = False


def authorize(signum, frame):
    global authorized
    authorized = True
    print('AUTHORIZED', flush=True)


signal.signal(signal.SIGUSR1, authorize)
signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
with socket.socket(family, socket.SOCK_DGRAM) as relay:
    relay.bind((host, 0))
    relay.settimeout(0.1)
    target = (host, int(target_port))
    peer = None
    flights = 0
    deadline = time.monotonic() + 30
    print(relay.getsockname()[1], flush=True)
    while time.monotonic() < deadline:
        try:
            packet, source = relay.recvfrom(65535)
        except socket.timeout:
            continue
        if source[:2] == target:
            if not authorized:
                print('FAIL: DTLS response before peer fingerprint', flush=True)
                sys.exit(1)
            assert peer is not None, 'server answered before a ClientHello'
            relay.sendto(packet, peer)
            continue
        if peer is None:
            peer = source
        assert source == peer, 'unexpected additional DTLS peer'
        if not authorized:
            assert len(packet) > 13 and packet[0] == 22 and packet[13] == 1, \
                'expected a real DTLS ClientHello'
            flights += 1
        relay.sendto(packet, target)
        if not authorized and flights == 3:
            print('PREAUTH_CLIENTHELLOS_IGNORED', flush=True)
    raise TimeoutError('DTLS preauthorization probe was not cleaned up')
