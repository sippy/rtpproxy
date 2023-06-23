# Official images of the RTPproxy Project

[![Clean Build@GitHub](https://github.com/sippy/rtpproxy/actions/workflows/cleanbuild.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/cleanbuild.yml?query=branch%3Amaster++)
[![All-inclusive Build@GitHub](https://github.com/sippy/rtpproxy/actions/workflows/depsbuild.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/depsbuild.yml?query=branch%3Amaster++)
[![Functional Testing@GitHub](https://github.com/sippy/rtpproxy/actions/workflows/functesting.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/functesting.yml?query=branch%3Amaster++)
[![Glitching@GitHub](https://github.com/sippy/rtpproxy/actions/workflows/glitching.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/glitching.yml?query=branch%3Amaster++)
[![OSSFuzz@GitHub](https://github.com/sippy/rtpproxy/actions/workflows/cifuzz.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/cifuzz.yml?query=branch%3Amaster++)
[![Coverage Status](https://coveralls.io/repos/github/sippy/rtpproxy/badge.svg?branch=master)](https://coveralls.io/github/sippy/rtpproxy?branch=master)
[![Coverity](https://scan.coverity.com/projects/8841/badge.svg)](https://scan.coverity.com/projects/sippy-rtpproxy)

## About

The RTPproxy is a extremely reliable and reasonably high-performance software
proxy for RTP streams that can work together with [OpenSIPS](https://opensips.org),
[Kamailio](https://kamailio.org) or [Sippy B2BUA](https://github.com/sippy/b2bua).

Originally created for handling NAT scenarios, back in 2004-2005, it can also act
as a generic real time datagram relay as well as gateway Real-Time Protocol (RTP)
sessions between IPv4 and IPv6 networks.

The RTPproxy supports many advanced features and is controllable over
multitude of Layer 4 protocols, including Unix Domain, UDP, UDPv6, TCP and TCPv6.

The software allows building scalable distributed SIP networks. The rtpproxy module
included into the OpenSIPS or Kamailio SIP Proxy software allows using multiple
RTPproxy instances running on remote machines for fault-tolerance and
load-balancing purposes.

The image  is updated on every commit to the https://github.com/sippy/rtpproxy/
repository.
