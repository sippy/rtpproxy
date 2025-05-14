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

#include "config_pp.h"

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_socket.h"
#include "rtpp_socket_fin.h"
#include "rtpp_netio_async.h"
#include "rtpp_mallocs.h"
#include "rtpp_time.h"
#include "rtpp_network.h"
#include "rtpp_network_io.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_debug.h"

struct rs_recv_arg {
    struct rtpp_socket_priv *pvt;
    const struct rtpp_timestamp *dtime;
    const struct sockaddr *laddr;
    int port;
};

DEFINE_RAW_METHOD(rs_rtp_recv, struct rtp_packet *, const struct rs_recv_arg *);

struct rtpp_socket_priv {
    struct rtpp_socket pub;
    struct rtpp_anetio_cf *netio;
    int fd;
    int type;
    uint64_t stuid;
    rs_rtp_recv_t rtp_recv;
};

static void rtpp_socket_dtor(struct rtpp_socket_priv *);
static int rtpp_socket_bind(struct rtpp_socket *, const struct sockaddr *,
  int);
static int rtpp_socket_settos(struct rtpp_socket *, int);
static int rtpp_socket_setrbuf(struct rtpp_socket *, int);
static int rtpp_socket_setnonblock(struct rtpp_socket *);
static int rtpp_socket_settimestamp(struct rtpp_socket *);
static int rtpp_socket_send_pkt_na(struct rtpp_socket *, struct sthread_args *,
  struct rtpp_netaddr *, struct rtp_packet *, struct rtpp_log *);
static struct rtp_packet * rtpp_socket_rtp_recv(struct rtpp_socket *,
  const struct rtpp_timestamp *, const struct sockaddr *, int);
static struct rtp_packet * rtpp_socket_rtp_recv_simple(const struct rs_recv_arg *);
static struct rtp_packet *rtpp_socket_rtp_recv_gen(const struct rs_recv_arg *);
static int rtpp_socket_getfd(struct rtpp_socket *);
static int rtpp_socket_drain(struct rtpp_socket *, const char *,
  struct rtpp_log *);
static void rtpp_socket_set_stuid(struct rtpp_socket *, uint64_t);
static uint64_t rtpp_socket_get_stuid(struct rtpp_socket *);

#if HAVE_SO_TS_CLOCK
static struct rtp_packet *rtpp_socket_rtp_recv_mono(const struct rs_recv_arg *);
#endif

DEFINE_SMETHODS(rtpp_socket,
    .bind2 = &rtpp_socket_bind,
    .settos = &rtpp_socket_settos,
    .setrbuf = &rtpp_socket_setrbuf,
    .setnonblock = &rtpp_socket_setnonblock,
    .settimestamp = &rtpp_socket_settimestamp,
    .send_pkt_na = &rtpp_socket_send_pkt_na,
    .rtp_recv = &rtpp_socket_rtp_recv,
    .getfd = &rtpp_socket_getfd,
    .drain = &rtpp_socket_drain,
    .set_stuid = &rtpp_socket_set_stuid,
    .get_stuid = &rtpp_socket_get_stuid,
);

struct rtpp_socket *
rtpp_socket_ctor(struct rtpp_anetio_cf *netio, int domain, int type)
{
    struct rtpp_socket_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_socket_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->fd = socket(domain, type, 0);
    pvt->netio = netio;
    if (pvt->fd < 0) {
        goto e1;
    }
    pvt->type = type;
    if (domain == AF_INET6) {
        /* Disable any automatic IPv4->IPv6 gatewaying */
        int yes = 1;

        setsockopt(pvt->fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
    }
    pvt->rtp_recv = &rtpp_socket_rtp_recv_simple;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_socket_dtor);
    return (&pvt->pub);
e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
rtpp_socket_dtor(struct rtpp_socket_priv *pvt)
{

    rtpp_socket_fin(&pvt->pub);
    if (pvt->type != SOCK_DGRAM) {
        shutdown(pvt->fd, SHUT_RDWR);
    }
    close(pvt->fd);
}

static int
rtpp_socket_bind(struct rtpp_socket *self, const struct sockaddr *addr,
  int addrlen)
{
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    return (bind(pvt->fd, addr, addrlen));
}

static int
rtpp_socket_settos(struct rtpp_socket *self, int tos)
{
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    return (setsockopt(pvt->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
}

static int
rtpp_socket_setrbuf(struct rtpp_socket *self, int so_rcvbuf)
{
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    return (setsockopt(pvt->fd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf,
      sizeof(so_rcvbuf)));
}

static int
rtpp_socket_setnonblock(struct rtpp_socket *self)
{
    int flags;
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    flags = fcntl(pvt->fd, F_GETFL);
    if (flags < 0)
        return (flags);
    return (fcntl(pvt->fd, F_SETFL, flags | O_NONBLOCK));
}

static int
rtpp_socket_settimestamp(struct rtpp_socket *self)
{
    struct rtpp_socket_priv *pvt;
    int sval, rval;

    PUB2PVT(self, pvt);
    sval = 1;
    rval = setsockopt(pvt->fd, SOL_SOCKET, SO_TIMESTAMP, &sval,
      sizeof(sval));
    if (rval != 0) {
        return (rval);
    }
    sval = 1;
#if defined(IP_RECVDSTADDR)
    setsockopt(pvt->fd, IPPROTO_IP, IP_RECVDSTADDR, &sval, sizeof(sval));
#else
    setsockopt(pvt->fd, IPPROTO_IP, IP_PKTINFO, &sval, sizeof(sval));
#endif
#if HAVE_SO_TS_CLOCK
    sval = SO_TS_MONOTONIC;
    rval = setsockopt(pvt->fd, SOL_SOCKET, SO_TS_CLOCK, &sval,
      sizeof(sval));
    if (rval == 0) {
        pvt->rtp_recv = &rtpp_socket_rtp_recv_mono;
        return (0);
    }
#endif
    pvt->rtp_recv = &rtpp_socket_rtp_recv_gen;
    return (0);
}

static int
rtpp_socket_send_pkt_na(struct rtpp_socket *self, struct sthread_args *str,
  struct rtpp_netaddr *daddr, struct rtp_packet *pkt,
  struct rtpp_log *log)
{
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    if (str == NULL)
        str = rtpp_anetio_pick_sender(pvt->netio);
    return (rtpp_anetio_send_pkt_na(str, pvt->fd, daddr, pkt,
      self->rcnt, log));
}

static struct rtp_packet *
rtpp_socket_rtp_recv(struct rtpp_socket *self, const struct rtpp_timestamp *dtime,
  const struct sockaddr *laddr, int port)
{
    struct rtpp_socket_priv *pvt;
    PUB2PVT(self, pvt);
    struct rs_recv_arg arg = {pvt, dtime, laddr, port};
    return (pvt->rtp_recv(&arg));
}

static struct rtp_packet *
rtpp_socket_rtp_recv_simple(const struct rs_recv_arg *ra)
{
    struct rtp_packet *packet;

    packet = rtp_packet_alloc();
    if (packet == NULL) {
        return NULL;
    }

    packet->rlen = sizeof(packet->raddr);
    packet->size = recvfrom(ra->pvt->fd, packet->data.buf, sizeof(packet->data.buf), 0, 
      sstosa(&packet->raddr), &packet->rlen);

    if (packet->size == -1) {
        RTPP_OBJ_DECREF(packet);
        return (NULL);
    }
    packet->laddr = ra->laddr;
    packet->lport = ra->port;
    if (ra->dtime != NULL) {
        packet->rtime.wall = ra->dtime->wall;
        packet->rtime.mono = ra->dtime->mono;
    }

    return (packet);
}

DEFINE_RAW_METHOD(recvfromto, ssize_t, int, void *, size_t, struct sockaddr *,
  socklen_t *, struct sockaddr *, socklen_t *, struct timespec *);

static struct rtp_packet *
_rtpp_socket_rtp_recv(const struct rs_recv_arg *ra, recvfromto_t _recvfromtof, struct timespec *tptr)
{
    struct rtp_packet *packet;
    socklen_t llen;

    packet = rtp_packet_alloc();
    if (packet == NULL) {
        return NULL;
    }

    packet->rlen = sizeof(packet->raddr);
    llen = sizeof(packet->_laddr);
    packet->size = _recvfromtof(ra->pvt->fd, packet->data.buf, sizeof(packet->data.buf),
      sstosa(&packet->raddr), &packet->rlen, sstosa(&packet->_laddr), &llen, tptr);

    if (packet->size == -1) {
        RTPP_OBJ_DECREF(packet);
        return (NULL);
    }
    if (llen > 0) {
        setport(sstosa(&packet->_laddr), ra->port);
        packet->laddr = sstosa(&packet->_laddr);
    } else {
        packet->laddr = ra->laddr;
    }
    packet->lport = ra->port;
    return (packet);
}

static struct rtp_packet *
rtpp_socket_rtp_recv_ts(const struct rs_recv_arg *ra, recvfromto_t recv_f)
{
    struct rtp_packet *packet;
    struct timespec rtime;

    memset(&rtime, '\0', sizeof(rtime));
    packet = _rtpp_socket_rtp_recv(ra, recv_f, &rtime);
    if (packet == NULL || ra->dtime == NULL) {
        goto out;
    }

    if (!timespeciszero(&rtime)) {
        packet->rtime.wall = timespec2dtime(&rtime);
    } else {
        packet->rtime.wall = ra->dtime->wall;
    }
    RTPP_DBG_ASSERT(packet->rtime.wall > 0);
    packet->rtime.mono = ra->dtime->mono;

out:
    return (packet);
}

static struct rtp_packet *
rtpp_socket_rtp_recv_gen(const struct rs_recv_arg *ra)
{

    return (rtpp_socket_rtp_recv_ts(ra, recvfromto));
}

#if HAVE_SO_TS_CLOCK
static struct rtp_packet *
rtpp_socket_rtp_recv_mono(const struct rs_recv_arg *ra)
{

    return (rtpp_socket_rtp_recv_ts(ra, recvfromto_mono));
}
#endif

static int
rtpp_socket_getfd(struct rtpp_socket *self)
{
    struct rtpp_socket_priv *pvt;

    PUB2PVT(self, pvt);
    return (pvt->fd);
}

static int
rtpp_socket_drain(struct rtpp_socket *self, const char *ptype,
  struct rtpp_log *log)
{
    int ndrained, rval;
    struct rtpp_socket_priv *pvt;
    static unsigned char scrapbuf[MAX_RPKT_LEN];

    PUB2PVT(self, pvt);
    ndrained = 0;
    RTPP_DBGCODE() {
        RTPP_LOG(log, RTPP_LOG_DBUG, "Draining %s socket %d", ptype,
          pvt->fd);
    }
    for (;;) {
        rval = recv(pvt->fd, scrapbuf, sizeof(scrapbuf), 0);
        if (rval < 0)
            break;
        ndrained++;
    }
    RTPP_DBGCODE() {
        if (ndrained > 0) {
            RTPP_LOG(log, RTPP_LOG_DBUG, "Draining %s socket %d: %d "
              "packets discarded", ptype, pvt->fd, ndrained);
        }
    }
    return (ndrained);
}

static void
rtpp_socket_set_stuid(struct rtpp_socket *self, uint64_t stuid)
{
    struct rtpp_socket_priv *pvt;
    PUB2PVT(self, pvt);

    pvt->stuid = stuid;
}

static uint64_t
rtpp_socket_get_stuid(struct rtpp_socket *self)
{
    struct rtpp_socket_priv *pvt;
    PUB2PVT(self, pvt);

    return (pvt->stuid);
}
