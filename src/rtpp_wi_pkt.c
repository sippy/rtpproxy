/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_network.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"
#include "rtpp_netaddr.h"

struct rtpp_wi_sendto {
    struct rtpp_wi_pvt wip;
    struct sockaddr_storage to;
    char msg[0];
};

static void rtpp_wi_free(struct rtpp_wi *);
static void rtpp_wi_pkt_free(struct rtpp_wi *);

static const struct rtpp_wi_sendto rtpp_wi_sendto_i = {
   .wip = {
       .pub = {
           .dtor = rtpp_wi_free,
           .wi_type = RTPP_WI_TYPE_OPKT
       },
       .nsend = 1
   }
};

struct rtpp_wi *
rtpp_wi_malloc(int sock, const void *msg, size_t msg_len, int flags,
  const struct sockaddr *sendto, size_t tolen)
{
    struct rtpp_wi_sendto *wis;

    wis = malloc(sizeof(struct rtpp_wi_sendto) + msg_len);
    if (wis == NULL) {
        return (NULL);
    }
    *wis = rtpp_wi_sendto_i;
    wis->wip.free_ptr = wis;
    wis->wip.sock = sock;
    wis->wip.flags = flags;
    wis->wip.msg = &(wis->msg);
    wis->wip.sendto = sstosa(&(wis->to));
    wis->wip.msg_len = msg_len;
    memcpy(wis->msg, msg, msg_len);
    wis->wip.tolen = tolen;
    memcpy(&(wis->to), sendto, tolen);
    return (&(wis->wip.pub));
}

struct rtpp_wi *
rtpp_wi_malloc_pkt(int sock, struct rtp_packet *pkt,
  const struct sockaddr *sendto, size_t tolen, int nsend,
  struct rtpp_refcnt *sock_rcnt)
{
    struct rtpp_wi_pvt *wipp;

    PUB2PVT(pkt->wi, wipp);
    wipp->pub.dtor = rtpp_wi_pkt_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_OPKT;
    wipp->free_ptr = (struct rtpp_wi *)pkt;
    wipp->sock = sock;
    if (sock_rcnt != NULL) {
        RC_INCREF(sock_rcnt);
    }
    wipp->sock_rcnt = sock_rcnt;
    wipp->flags = 0;
    wipp->msg = pkt->data.buf;
    wipp->msg_len = pkt->size;
    wipp->sendto = sstosa(&pkt->sendto);
    wipp->tolen = tolen;
    memcpy(wipp->sendto, sendto, tolen);
    wipp->nsend = nsend;
    return (&(wipp->pub));
}

struct rtpp_wi *
rtpp_wi_malloc_pkt_na(int sock, struct rtp_packet *pkt,
  struct rtpp_netaddr *sendto, int nsend,
  struct rtpp_refcnt *sock_rcnt)
{
    struct rtpp_wi_pvt *wipp;

    PUB2PVT(pkt->wi, wipp);
    wipp->pub.dtor = rtpp_wi_pkt_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_OPKT;
    wipp->free_ptr = (struct rtpp_wi *)pkt;
    wipp->sock = sock;
    if (sock_rcnt != NULL) {
        RC_INCREF(sock_rcnt);
    }
    wipp->sock_rcnt = sock_rcnt;
    wipp->flags = 0;
    wipp->msg = pkt->data.buf;
    wipp->msg_len = pkt->size;
    wipp->sendto = sstosa(&pkt->sendto);
    wipp->tolen = CALL_SMETHOD(sendto, get, wipp->sendto, sizeof(pkt->raddr));
    wipp->nsend = nsend;
    return (&(wipp->pub));
}

static void
rtpp_wi_free(struct rtpp_wi *wi)
{
    struct rtpp_wi_pvt *wipp;

    PUB2PVT(wi, wipp);
    if (wipp->log != NULL) {
        RTPP_OBJ_DECREF(wipp->log);
    }
    free(wipp->free_ptr);
}

static void
rtpp_wi_pkt_free(struct rtpp_wi *wi)
{
    struct rtpp_wi_pvt *wipp;
    struct rtp_packet *pkt;

    PUB2PVT(wi, wipp);
    if (wipp->sock_rcnt != NULL) {
        RC_DECREF(wipp->sock_rcnt);
    }
    if (wipp->log != NULL) {
        RTPP_OBJ_DECREF(wipp->log);
    }
    pkt = (struct rtp_packet *)wipp->free_ptr;
    RTPP_OBJ_DECREF(pkt);
}
