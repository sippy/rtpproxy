# Official images of the RTPproxy Project

[![RTPProxy CI](https://github.com/sippy/rtpproxy/actions/workflows/rtpproxy_ci.yml/badge.svg?branch=master)](https://github.com/sippy/rtpproxy/actions/workflows/rtpproxy_ci.yml?query=branch%3Amaster++)
[![Coverage Status](https://coveralls.io/repos/github/sippy/rtpproxy/badge.svg?branch=master)](https://coveralls.io/github/sippy/rtpproxy?branch=master)
[![Coverity](https://scan.coverity.com/projects/8841/badge.svg)](https://scan.coverity.com/projects/sippy-rtpproxy)

## What is RTPproxy?

RTPproxy is a robust, high-performance software proxy engineered to manage
Real-Time Protocol (RTP) streams. It integrates seamlessly with
[OpenSIPS](https://opensips.org), [Kamailio](https://kamailio.org), and
[Sippy B2BUA](https://github.com/sippy/b2bua), making it a versatile tool for
various network applications.

Developed in 2004-2005 for NAT scenarios, RTPproxy has expanded its functionality
over time. Beyond acting as a general-purpose datagram relay and bridging RTP
sessions between IPv4 and IPv6 networks, it now supports translation between DTLS
and unencrypted RTP channels, call recording, call forking, and audio prompt
injection into RTP streams for applications like Music on Hold (MOH) and
announcements.

Equipped with advanced features, RTPproxy offers control through several Layer 4
protocols, including Unix Domain, UDP, UDPv6, TCP, and TCPv6.

RTPproxy is crucial for constructing scalable, distributed SIP networks and
developing SIP/VoIP/RTC products and services. It's been an integral part of
related open-source projects like DD-WRT for over a decade.

Incorporating the rtpproxy module into OpenSIPS or Kamailio SIP Proxy software
allows deploying multiple RTPproxy instances across machines for enhanced
fault tolerance and load balancing.

Updates to the Docker image for RTPproxy are pushed with every commit to the
[official RTPproxy repository](https://github.com/sippy/rtpproxy/), keeping users
current with the latest enhancements.
