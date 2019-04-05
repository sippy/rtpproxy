[![Build Status](https://travis-ci.org/sippy/rtpproxy.svg?branch=master)](https://travis-ci.org/sippy/rtpproxy)
[![Coverage Status](https://coveralls.io/repos/github/sippy/rtpproxy/badge.svg?branch=master)](https://coveralls.io/github/sippy/rtpproxy?branch=master)

## About

The RTPproxy is a high-performance software proxy for RTP streams that can
work together with [OpenSIPS](https://opensips.org), [Kamailio](https://kamailio.org)
or [Sippy B2BUA](https://github.com/sippy/b2bua).

Originally created for handling NAT scenarios it can also act as a generic
media relay as well as gateway RTP sessions between IPv4 and IPv6 networks.

The RTPproxy supports some advanced features, such as remote control mode,
allowing building scalable distributed SIP VoIP networks. The nathelper module
included into the OpenSIPS or Kamailio SIP Proxy software allows using multiple
RTPproxy instances running on remote machines for fault-tolerance and
load-balancing purposes.

Advanced high-capacity clustering and load balancing is available through the
use of [RTP Cluster](https://github.com/sippy/rtp_cluster) middleware.

The software also supports MOH/pre-recorded prompts injection,  video relaying
and RTP session recording to a local file or remote UDP listener(s).

RTPproxy was developed by Maxim Sobolev and now is being actively maintained
by the [Sippy Software, Inc](http://www.sippysoft.com).

## How it works

This proxy works as follows:

- When SER receives INVITE request, it extracts call-id from it and
  communicates it to the proxy via Unix domain socket. Proxy looks for an
  existing sessions with such id, if the session exists it returns UDP port
  for that session, if not, then it creates a new session, binds to a first
  empty UDP port from the range specified at the compile time and returns
  number of that port to a SER. After receiving reply from the proxy, SER
  replaces media ip:port in the SDP to point to the proxy and forwards
  request as usually;

- when SER receives non-negative SIP reply with SDP it again extracts
  call-id from it and communicates it to the proxy. In this case the proxy
  does not allocate a new session if it doesn't exist, but simply performs a
  lookup among existing sessions and returns either a port number if the
  session is found, or error code indicating that there is no session with
  such id. After receiving positive reply from the proxy, SER replaces media
  ip:port in the SIP reply to point to the proxy and forwards reply as
  usually;

- after the session has been created, the proxy listens on the port it has
  allocated for that session and waits for receiving at least one UDP
  packet from each of two parties participating in the call. Once such
  packet is received, the proxy fills one of two ip:port structures
  associated with each call with source ip:port of that packet. When both
  structures are filled in, the proxy starts relaying UDP packets between
  parties;

- the proxy tracks idle time for each of existing sessions (i.e. the time
  within which there were no packets relayed), and automatically cleans
  up a sessions whose idle times exceed the value specified at compile
  time (60 seconds by default).

## Building from github

```
$ git clone -b master https://github.com/sippy/rtpproxy.git
$ git -C rtpproxy submodule update --init --recursive
$ cd rtpproxy
$ ./configure
$ make
```

## Support

Open a ticket on the github issue tracker, or post a message on the [mailing
list](https://groups.google.com/forum/#!forum/rtpproxy)

Commercial support is available from the Sippy Software, Inc. - visit
http://www.sippysoft.com for details.
