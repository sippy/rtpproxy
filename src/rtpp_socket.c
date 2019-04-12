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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_socket.h"
#include "rtpp_socket_fin.h"
#include "rtpp_netio_async.h"
#include "rtpp_mallocs.h"
#include "rtpp_time.h"
#include "rtpp_network.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_debug.h"

struct rtpp_socket_priv {
    struct rtpp_socket pub;
    int fd;
};

static void rtpp_socket_dtor(struct rtpp_socket_priv *);
static int rtpp_socket_bind(struct rtpp_socket *, const struct sockaddr *,
  int);
static int rtpp_socket_settos(struct rtpp_socket *, int);
static int rtpp_socket_setrbuf(struct rtpp_socket *, int);
static int rtpp_socket_setnonblock(struct rtpp_socket *);
static int rtpp_socket_settimestamp(struct rtpp_socket *);
#if 0
static int rtpp_socket_send_pkt(struct rtpp_socket *, struct sthread_args *,
  const struct sockaddr *, int, struct rtp_packet *, struct rtpp_log *);
#endif
static int rtpp_socket_send_pkt_na(struct rtpp_socket *, struct sthread_args *,
  struct rtpp_netaddr *, struct rtp_packet *, struct rtpp_log *);
static struct rtp_packet * rtpp_socket_rtp_recv_simple(struct rtpp_socket *,
  const struct rtpp_timestamp *, struct sockaddr *, int);
static struct rtp_packet *rtpp_socket_rtp_recv(struct rtpp_socket *,
  const struct rtpp_timestamp *, struct sockaddr *, int);
static int rtpp_socket_getfd(struct rtpp_socket *);

#define PUB2PVT(pubp) \
  ((struct rtpp_socket_priv *)((char *)(pubp) - offsetof(struct rtpp_socket_priv, pub)))

struct rtpp_socket *
rtpp_socket_ctor(int domain, int type)
{
    struct rtpp_socket_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_socket_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->fd = socket(domain, type, 0);
    if (pvt->fd < 0) {
        goto e1;
    }
    if (domain == AF_INET6) {
        /* Disable any automatic IPv4->IPv6 gatewaying */
        int yes = 1;

        setsockopt(pvt->fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
    }
    pvt->pub.bind = &rtpp_socket_bind;
    pvt->pub.settos = &rtpp_socket_settos;
    pvt->pub.setrbuf = &rtpp_socket_setrbuf;
    pvt->pub.setnonblock = &rtpp_socket_setnonblock;
    pvt->pub.settimestamp = &rtpp_socket_settimestamp;
#if 0
    pvt->pub.send_pkt = &rtpp_socket_send_pkt;
#endif
    pvt->pub.send_pkt_na = &rtpp_socket_send_pkt_na;
    pvt->pub.rtp_recv = &rtpp_socket_rtp_recv_simple;
    pvt->pub.getfd = &rtpp_socket_getfd;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_socket_dtor,
      pvt);
    return (&pvt->pub);
e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_socket_dtor(struct rtpp_socket_priv *pvt)
{

    rtpp_socket_fin(&pvt->pub);
    shutdown(pvt->fd, SHUT_RDWR);
    close(pvt->fd);
    free(pvt);
}

static int
rtpp_socket_bind(struct rtpp_socket *self, const struct sockaddr *addr,
  int addrlen)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (bind(pvt->fd, addr, addrlen));
}

static int
rtpp_socket_settos(struct rtpp_socket *self, int tos)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (setsockopt(pvt->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
}

static int
rtpp_socket_setrbuf(struct rtpp_socket *self, int so_rcvbuf)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (setsockopt(pvt->fd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf,
      sizeof(so_rcvbuf)));
}

static int
rtpp_socket_setnonblock(struct rtpp_socket *self)
{
    int flags;
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    flags = fcntl(pvt->fd, F_GETFL);
    return (fcntl(pvt->fd, F_SETFL, flags | O_NONBLOCK));
}

static int
rtpp_socket_settimestamp(struct rtpp_socket *self)
{
    struct rtpp_socket_priv *pvt;
    int sval, rval;

    pvt = PUB2PVT(self);
    sval = 1;
    rval = setsockopt(pvt->fd, SOL_SOCKET, SO_TIMESTAMP, &sval,
      sizeof(sval));
    if (rval != 0) {
        return (rval);
    }
    pvt->pub.rtp_recv = &rtpp_socket_rtp_recv;
    return (0);
}

#if 0
static int 
rtpp_socket_send_pkt(struct rtpp_socket *self, struct sthread_args *str,
  const struct sockaddr *daddr, int addrlen, struct rtp_packet *pkt,
  struct rtpp_log *log)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (rtpp_anetio_send_pkt(str, pvt->fd, daddr, addrlen, pkt,
      self->rcnt, log));
}
#endif

static int
rtpp_socket_send_pkt_na(struct rtpp_socket *self, struct sthread_args *str,
  struct rtpp_netaddr *daddr, struct rtp_packet *pkt,
  struct rtpp_log *log)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (rtpp_anetio_send_pkt_na(str, pvt->fd, daddr, pkt,
      self->rcnt, log));
}

static struct rtp_packet *
rtpp_socket_rtp_recv_simple(struct rtpp_socket *self, const struct rtpp_timestamp *dtime,
  struct sockaddr *laddr, int port)
{
    struct rtpp_socket_priv *pvt;
    struct rtp_packet *packet;

    packet = rtp_packet_alloc();
    if (packet == NULL) {
        return NULL;
    }

    pvt = PUB2PVT(self);

    packet->rlen = sizeof(packet->raddr);
    packet->size = recvfrom(pvt->fd, packet->data.buf, sizeof(packet->data.buf), 0, 
      sstosa(&packet->raddr), &packet->rlen);

    if (packet->size == -1) {
        rtp_packet_free(packet);
        return (NULL);
    }
    packet->laddr = laddr;
    packet->lport = port;
    if (dtime != NULL) {
        packet->rtime.wall = dtime->wall;
        packet->rtime.mono = dtime->mono;
    }

    return (packet);
}

static struct rtp_packet *
rtpp_socket_rtp_recv(struct rtpp_socket *self, const struct rtpp_timestamp *dtime,
  struct sockaddr *laddr, int port)
{
    struct rtpp_socket_priv *pvt;
    struct rtp_packet *packet;
    struct timeval rtime;
    size_t llen;

    packet = rtp_packet_alloc();
    if (packet == NULL) {
        return NULL;
    }

    pvt = PUB2PVT(self);

    packet->rlen = sizeof(packet->raddr);
    llen = sizeof(packet->_laddr);
    memset(&rtime, '\0', sizeof(rtime));
    packet->size = recvfromto(pvt->fd, packet->data.buf, sizeof(packet->data.buf),
      sstosa(&packet->raddr), &packet->rlen, sstosa(&packet->_laddr), &llen,
      &rtime);

    if (packet->size == -1) {
        rtp_packet_free(packet);
        return (NULL);
    }
    if (llen > 0) {
        packet->laddr = sstosa(&packet->_laddr);
        packet->lport = getport(packet->laddr);
    } else {
        packet->laddr = laddr;
        packet->lport = port;
    }
    if (!timevaliszero(&rtime)) {
        packet->rtime.wall = timeval2dtime(&rtime);
    } else {
        packet->rtime.wall = dtime->wall;
    }
    RTPP_DBG_ASSERT(packet->rtime.wall > 0);
    packet->rtime.mono = dtime->mono;

    return (packet);
}

static int
rtpp_socket_getfd(struct rtpp_socket *self)
{
    struct rtpp_socket_priv *pvt;

    pvt = PUB2PVT(self);
    return (pvt->fd);
}
