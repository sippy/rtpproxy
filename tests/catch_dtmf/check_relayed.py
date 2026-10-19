#!/usr/bin/env python3
#
# Check that the RTPProxy packets recorded into RELAYED have all been
# sent from SPORT and carry the same payloads, in the same order, as the
# packets sent to DPORT in the replayed ORIG capture.

import struct, sys

def read_pcap(fname):
    with open(fname, 'rb') as f:
        data = f.read()
    if struct.unpack('<I', data[:4])[0] != 0xa1b2c3d4 or \
      struct.unpack('<I', data[20:24])[0] != 1:
        raise Exception(F'{fname}: not a little-endian Ethernet PCAP file')
    off, pkts = 24, []
    while off < len(data):
        caplen = struct.unpack('<I', data[off + 8:off + 12])[0]
        ip = data[off + 30:off + 16 + caplen]
        off += 16 + caplen
        ihl = (ip[0] & 0xf) * 4
        sport, dport, ulen = struct.unpack('!HHH', ip[ihl:ihl + 6])
        pkts.append((sport, dport, ip[ihl + 8:ihl + ulen]))
    return pkts

def main(relayed, sport, orig, dport):
    rpkts = read_pcap(relayed)
    bad = [p for p in rpkts if p[0] != sport]
    if len(bad) > 0:
        sys.stderr.write(F'{len(bad)} packets sent from unexpected ports: '
          F'{sorted(set(p[0] for p in bad))}\n')
        return 1
    exp = [p[2] for p in read_pcap(orig) if p[1] == dport]
    got = [p[2] for p in rpkts]
    if got != exp:
        sys.stderr.write(F'payloads mismatch: got {len(got)} packets, '
          F'expected {len(exp)}\n')
        return 1
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 5:
        sys.stderr.write('usage: check_relayed.py RELAYED SPORT ORIG DPORT\n')
        sys.exit(2)
    sys.exit(main(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])))
