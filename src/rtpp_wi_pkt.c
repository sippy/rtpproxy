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
#include "rtpp_mallocs.h"
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

static void rtpp_wi_free(struct rtpp_wi_sendto *);
static void rtpp_wi_pkt_free(struct rtpp_wi_pvt *);

struct rtpp_wi *
rtpp_wi_malloc(int sock, const void *msg, size_t msg_len, int flags,
  const struct sockaddr *sendto, size_t tolen)
{
    struct rtpp_wi_sendto *wis;

    wis = rtpp_rmalloc(sizeof(struct rtpp_wi_sendto) + msg_len, PVT_RCOFFS(&wis->wip));
    if (wis == NULL) {
        return (NULL);
    }
    wis->wip.pub.wi_type = RTPP_WI_TYPE_OPKT;
    wis->wip.pub.next = NULL;
    wis->wip.nsend = 1;
    wis->wip.sock = sock;
    wis->wip.flags = flags;
    wis->wip.msg = &(wis->msg);
    wis->wip.sendto = sstosa(&(wis->to));
    wis->wip.msg_len = msg_len;
    memcpy(wis->msg, msg, msg_len);
    wis->wip.tolen = tolen;
    memcpy(&(wis->to), sendto, tolen);
    CALL_SMETHOD(wis->wip.pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_wi_free,
      wis);
    return (&(wis->wip.pub));
}

struct rtpp_wi *
rtpp_wi_malloc_pkt_na(int sock, struct rtp_packet *pkt,
  struct rtpp_netaddr *sendto, int nsend,
  struct rtpp_refcnt *sock_rcnt)
{
    struct rtpp_wi_pvt *wipp;

    PUB2PVT(pkt->wi, wipp);
    wipp->pub.rcnt = pkt->rcnt;
    wipp->pub.wi_type = RTPP_WI_TYPE_OPKT;
    wipp->pub.next = NULL;
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
    CALL_SMETHOD(pkt->rcnt, reg_pd, (rtpp_refcnt_dtor_t)rtpp_wi_pkt_free,
      wipp);
    return (&(wipp->pub));
}

static void
rtpp_wi_free(struct rtpp_wi_sendto *wis)
{

    if (wis->wip.log != NULL) {
        RTPP_OBJ_DECREF(wis->wip.log);
    }
    free(wis);
}

static void
rtpp_wi_pkt_free(struct rtpp_wi_pvt *wipp)
{

    if (wipp->sock_rcnt != NULL) {
        RC_DECREF(wipp->sock_rcnt);
    }
    if (wipp->log != NULL) {
        RTPP_OBJ_DECREF(wipp->log);
    }
}
