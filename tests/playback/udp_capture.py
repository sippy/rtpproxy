#!/usr/bin/env python3
#
# Capture UDP packets sent to the 127.0.0.1 and ::1 sockets and save the IPv4
# ones into a PCAP file, so that the test does not need root privileges to run
# tcpdump. Also binds two sockets that are never read, to be used as
# addresses that nothing should be sent to.
#
# Prints "PORT4 PORT6 TRASH4 TRASH6" once ready, then exits as soon as NPKTS
# packets have been received on each of the capture sockets. The list of
# distinct TOS values of the IPv4 packets is written into TOSFILE.

import socket, select, struct, sys, time

def ip_cksum(hdr):
    s = sum(struct.unpack('!10H', hdr))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def pcap_record(ts, src, dst, tos, data):
    udp = struct.pack('!HHHH', src[1], dst[1], 8 + len(data), 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(udp), 0, 0, 64,
      socket.IPPROTO_UDP, 0, socket.inet_aton(src[0]), socket.inet_aton(dst[0]))
    ip = ip[:10] + struct.pack('!H', ip_cksum(ip)) + ip[12:]
    # Ethernet header with zero MAC addresses
    frame = bytes(12) + struct.pack('!H', 0x0800) + ip + udp
    usec = int(ts * 1000000)
    return struct.pack('=IIII', usec // 1000000, usec % 1000000, len(frame),
      len(frame)) + frame

def main(npkts, pcapfile, tosfile, timeout = 60.0):
    socks = []
    for af, addr in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1'),
      (socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        s = socket.socket(af, socket.SOCK_DGRAM)
        s.bind((addr, 0))
        socks.append(s)
    s4, s6 = socks[:2]
    s4.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    print(' '.join(str(s.getsockname()[1]) for s in socks), flush = True)
    dst4 = s4.getsockname()
    records, toss, n6 = [], [], 0
    etime = time.monotonic() + timeout
    while len(records) < npkts or n6 < npkts:
        tleft = etime - time.monotonic()
        if tleft <= 0:
            sys.stderr.write(F'udp_capture: timeout, got {len(records)} IPv4 '
              F'and {n6} IPv6 packets out of {npkts}\n')
            return 1
        ready, _, _ = select.select((s4, s6), (), (), tleft)
        if s6 in ready:
            s6.recv(65536)
            n6 += 1
        if s4 in ready:
            data, ancdata, _, src = s4.recvmsg(65536, socket.CMSG_SPACE(4))
            if len(records) >= npkts:
                continue
            tos = 0
            for level, _, cdata in ancdata:
                if level == socket.IPPROTO_IP and len(cdata) > 0:
                    tos = cdata[0]
            records.append(pcap_record(time.time(), src, dst4, tos, data))
            if tos not in toss:
                toss.append(tos)
    with open(pcapfile, 'wb') as f:
        # PCAP 2.4, no snaplen limit, DLT_EN10MB
        f.write(struct.pack('=IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        f.write(b''.join(records))
    with open(tosfile, 'w') as f:
        f.write(' '.join('0x%02x' % tos for tos in toss) + '\n')
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stderr.write('usage: udp_capture.py NPKTS PCAPFILE TOSFILE\n')
        sys.exit(2)
    sys.exit(main(int(sys.argv[1]), sys.argv[2], sys.argv[3]))
