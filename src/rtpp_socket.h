/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

struct cfg;
struct rtpp_socket;
struct sockaddr;
struct rtp_packet;
struct sthread_args;
struct rtpp_log;
struct rtpp_netaddr;
struct rtpp_timestamp;

DEFINE_METHOD(rtpp_socket, rtpp_socket_bind, int, const struct sockaddr *,
  int);
DEFINE_METHOD(rtpp_socket, rtpp_socket_settos, int, int);
DEFINE_METHOD(rtpp_socket, rtpp_socket_setrbuf, int, int);
DEFINE_METHOD(rtpp_socket, rtpp_socket_setnonblock, int);
DEFINE_METHOD(rtpp_socket, rtpp_socket_settimestamp, int);
#if 0
/*DEFINE_METHOD(rtpp_socket, rtpp_socket_send_pkt, int,
  struct sthread_args *, const struct sockaddr *, int, struct rtp_packet *,
  struct rtpp_log *);*/
#endif
DEFINE_METHOD(rtpp_socket, rtpp_socket_send_pkt_na, int,
  struct sthread_args *, struct rtpp_netaddr *, struct rtp_packet *,
  struct rtpp_log *);
DEFINE_METHOD(rtpp_socket, rtpp_socket_rtp_recv, struct rtp_packet *,
  const struct rtpp_timestamp *, struct sockaddr *, int);
DEFINE_METHOD(rtpp_socket, rtpp_socket_getfd, int);

struct rtpp_socket {
    struct rtpp_refcnt *rcnt;
    /* Public methods */
    METHOD_ENTRY(rtpp_socket_bind, bind);
    METHOD_ENTRY(rtpp_socket_settos, settos);
    METHOD_ENTRY(rtpp_socket_setrbuf, setrbuf);
    METHOD_ENTRY(rtpp_socket_setnonblock, setnonblock);
    METHOD_ENTRY(rtpp_socket_settimestamp, settimestamp);
#if 0
    METHOD_ENTRY(rtpp_socket_send_pkt, send_pkt);
#endif
    METHOD_ENTRY(rtpp_socket_send_pkt_na, send_pkt_na);
    METHOD_ENTRY(rtpp_socket_rtp_recv, rtp_recv);
    METHOD_ENTRY(rtpp_socket_getfd, getfd);
};

struct rtpp_socket *rtpp_socket_ctor(int, int);
