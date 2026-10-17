[![RTPProxy CI](https://github.com/sippy/rtpproxy/actions/workflows/rtpproxy_ci.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/rtpproxy_ci.yml?query=branch%3Amaster++)
[![Coverage Status](https://coveralls.io/repos/github/sippy/rtpproxy/badge.svg?branch=master)](https://coveralls.io/github/sippy/rtpproxy?branch=master)
[![Coverity](https://scan.coverity.com/projects/8841/badge.svg)](https://scan.coverity.com/projects/sippy-rtpproxy)

## About

The RTPProxy is an extremely reliable and reasonably high-performance software
proxy for RTP streams that can work together with [OpenSIPS](https://opensips.org),
[Kamailio](https://kamailio.org) or [Sippy B2BUA](https://github.com/sippy/b2bua).

Originally created for handling NAT scenarios, back in 2003, it can also act
as a generic real time datagram relay as well as a gateway for Real-time Transport
Protocol (RTP) sessions between IPv4 and IPv6 networks.

The RTPProxy supports many advanced features and is controllable over
a multitude of Layer 4 protocols, including Unix Domain, UDP, UDPv6, TCP and TCPv6.

The software allows building scalable distributed SIP networks. The rtpproxy module
included into the OpenSIPS or Kamailio SIP Proxy software allows using multiple
RTPProxy instances running on remote machines for fault-tolerance and
load-balancing purposes.

Advanced high-capacity clustering and load balancing is available through the
use of [RTP Cluster](https://github.com/sippy/rtp_cluster) middleware.

The software also supports MOH/pre-recorded media injection, video relaying
and session recording to a local file or remote UDP listener(s). It also
makes available an array of real-time or near real-time session counters,
both per-session and per-instance.

Since version 3.1.0, a full set of extensions is available for creating
WebRTC-compatible endpoints.

## News

- RTPProxy 3.2.0 is out, see the [release notes](https://github.com/sippy/rtpproxy/releases/tag/v3.2.0);
- WebRTC clients are supported via the dtls_gw and ice_lite modules since 3.1.0.

## How it works

This proxy works as follows:

- When SIP Controller, either proxy or B2BUA, receives INVITE request, it
  extracts call-id from it and communicates it to the proxy via control
  channel. Proxy looks for an existing sessions with such id, if the session
  exists it returns UDP port for that session, if not, then it creates a new
  session, binds to a first available randomly selected pair of UDP ports and
  returns number of the first port. After receiving reply from the proxy, SIP
  Controller replaces media ip:port in the SDP to point to the proxy and
  forwards request as usually;

- when SIP Controller receives non-negative SIP reply with SDP it again
  extracts call-id along with session tags from it and communicates it to
  the proxy. In this case the proxy does not allocate a new session if it
  doesn't exist, but simply performs a lookup among existing sessions and
  returns either a port number if the session is found, or error code
  indicating that there is no session with such id. After receiving positive
  reply from the proxy, SIP Controller replaces media ip:port in the SIP
  reply to point to the proxy and forwards reply as usually;

- after the session has been created, the proxy listens on the ports it has
  allocated for that session and relays UDP packets between the parties.
  Initially, packets are sent to the addresses provided by the SIP
  Controller, i.e. taken from the SDP. Once a packet is received from a
  party, the proxy "latches" to the source ip:port of that packet and uses
  it as the address of that party from then on, which allows reaching
  parties located behind NAT. Latching is not done for asymmetric parties;

- the proxy tracks idle time for each of existing sessions (i.e. the time
  within which there were no packets relayed), and automatically cleans
  up sessions whose idle times exceed the value specified on the command
  line (60 seconds by default).

## Building from github

```
$ git clone -b master https://github.com/sippy/rtpproxy.git
$ git -C rtpproxy submodule update --init --recursive
$ cd rtpproxy
$ ./configure
$ make
```

## Authors and Contributors

The RTPProxy has been designed by Maxim Sobolev and is now actively
maintained by the [Sippy Software, Inc](http://www.sippysoft.com). With the
great help of numerous community contributors, both private and institutional.
Not to mention an army of robots gracefully dispatched at need by CI.

The original idea has inspired and directly influenced a multitude of independent
implementations, including but not limited to the
[MediaProxy](https://github.com/AGProjects/mediaproxy),
[erlrtpproxy](https://github.com/lemenkov/erlrtpproxy), and most recently
[RTP Engine](https://github.com/sipwise/rtpengine), each project focusing on
its own area of the vast functionality space.

## Documentation and References

- [User Manual](https://www.rtpproxy.org/doc/master/user_manual.html#MAKESRC);
- [RTPProxy Control Protocol Reference](https://github.com/sippy/rtpproxy/wiki/RTPProxy-Command-Protocol).

## Feedback & Support

Open a ticket on the github issue tracker, or post a message on the [mailing
list](https://groups.google.com/forum/#!forum/rtpproxy)
