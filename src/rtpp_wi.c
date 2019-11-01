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
    wipp->pub.dtor = rtpp_wi_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_OPKT;
    wipp->free_ptr = (struct rtpp_wi *)pkt;
    wipp->sock = sock;
    if (sock_rcnt != NULL) {
        CALL_SMETHOD(sock_rcnt, incref);
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
    wipp->pub.dtor = rtpp_wi_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_OPKT;
    wipp->free_ptr = (struct rtpp_wi *)pkt;
    wipp->sock = sock;
    if (sock_rcnt != NULL) {
        CALL_SMETHOD(sock_rcnt, incref);
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

struct rtpp_wi *
#if !defined(RTPP_CHECK_LEAKS)
rtpp_wi_malloc_sgnl(int signum, const void *data, size_t datalen)
#else
rtpp_wi_malloc_sgnl_memdeb(const char *fname, int linen, const char *funcn, int signum, const void *data, size_t datalen)
#endif
{
    struct rtpp_wi_pvt *wipp;
#if !defined(RTPP_CHECK_LEAKS)
    wipp = malloc(sizeof(struct rtpp_wi_pvt) + datalen);
#else
    wipp = rtpp_memdeb_malloc(sizeof(struct rtpp_wi_pvt) + datalen,
      MEMDEB_SYM, fname, linen, funcn);
#endif
    if (wipp == NULL) {
        return (NULL);
    }
    memset(wipp, '\0', sizeof(struct rtpp_wi_pvt));
    wipp->pub.dtor = rtpp_wi_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_SGNL;
    wipp->free_ptr = wipp;
    wipp->flags = signum;
    if (datalen > 0) {
        wipp->msg = wipp->data;
        wipp->msg_len = datalen;
        memcpy(wipp->data, data, datalen);
    }
    return (&(wipp->pub));
}

struct rtpp_wi_apis {
   struct rtpp_wi pub;
   const char *apiname;
   size_t msg_len;
   char msg[0];
};

static void
rtpp_wi_free_apis(struct rtpp_wi *wi)
{
    struct rtpp_wi_apis *wipp;

    PUB2PVT(wi, wipp);
    free(wipp);
}

static const struct rtpp_wi_apis rtpp_wi_apis_i = {
   .pub = {
       .dtor = rtpp_wi_free_apis,
       .wi_type = RTPP_WI_TYPE_API_STR
   }
};

struct rtpp_wi *
rtpp_wi_malloc_apis(const char *apiname, void *data, size_t datalen)
{
    struct rtpp_wi_apis *wipp;

    wipp = malloc(sizeof(struct rtpp_wi_apis) + datalen);
    if (wipp == NULL) {
        return (NULL);
    }
    *wipp = rtpp_wi_apis_i;
    wipp->apiname = apiname;
    if (datalen > 0) {
        wipp->msg_len = datalen;
        memcpy(wipp->msg, data, datalen);
    }
    return (&(wipp->pub));
}

struct rtpp_wi *
rtpp_wi_malloc_data(void *dataptr, size_t datalen)
{
    struct rtpp_wi_pvt *wipp;

    wipp = malloc(sizeof(struct rtpp_wi_pvt) + datalen);
    if (wipp == NULL) {
        return (NULL);
    }
    memset(wipp, '\0', sizeof(struct rtpp_wi_pvt));
    wipp->pub.dtor = rtpp_wi_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_DATA;
    wipp->free_ptr = wipp;
    if (datalen > 0) {
        wipp->msg = wipp->data;
        wipp->msg_len = datalen;
        memcpy(wipp->data, dataptr, datalen);
    }
    return (&(wipp->pub));
}

struct rtpp_wi *
rtpp_wi_malloc_udata(void **dataptr, size_t datalen)
{
    struct rtpp_wi_pvt *wipp;

    wipp = malloc(sizeof(struct rtpp_wi_pvt) + datalen);
    if (wipp == NULL) {
        return (NULL);
    }
    memset(wipp, '\0', sizeof(struct rtpp_wi_pvt));
    wipp->pub.dtor = rtpp_wi_free;
    wipp->pub.wi_type = RTPP_WI_TYPE_DATA;
    wipp->free_ptr = wipp;
    if (datalen > 0) {
        wipp->msg = wipp->data;
        wipp->msg_len = datalen;
        *dataptr = wipp->data;
    }
    return (&(wipp->pub));
}

void *
rtpp_wi_sgnl_get_data(struct rtpp_wi *wi, size_t *datalen)
{
    struct rtpp_wi_pvt *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    PUB2PVT(wi, wipp);
    if (datalen != NULL) {
        *datalen = wipp->msg_len;
    }
    return(wipp->msg);
}

int
rtpp_wi_sgnl_get_signum(struct rtpp_wi *wi)
{
    struct rtpp_wi_pvt *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    PUB2PVT(wi, wipp);
    return (wipp->flags);
}

void *
rtpp_wi_data_get_ptr(struct rtpp_wi *wi, size_t min_len, size_t max_len)
{
    struct rtpp_wi_pvt *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_DATA);
    PUB2PVT(wi, wipp);
    assert(wipp->msg_len >= min_len);
    assert(max_len == 0 || wipp->msg_len <= max_len);

    return(wipp->msg);
}

const char *
rtpp_wi_apis_getname(struct rtpp_wi *wi)
{
    struct rtpp_wi_apis *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_API_STR);
    PUB2PVT(wi, wipp);
    return (wipp->apiname);
}

const char *
rtpp_wi_apis_getnamearg(struct rtpp_wi *wi, void **datap, size_t datalen)
{
    struct rtpp_wi_apis *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_API_STR);
    PUB2PVT(wi, wipp);
    assert(wipp->msg_len == datalen);
    if (datap != NULL && datalen > 0) {
        memcpy(datap, wipp->msg, datalen);
    }
    return (wipp->apiname);
}

static void
rtpp_wi_free(struct rtpp_wi *wi)
{
    struct rtpp_wi_pvt *wipp;

    PUB2PVT(wi, wipp);
    if (wipp->sock_rcnt != NULL) {
        CALL_SMETHOD(wipp->sock_rcnt, decref);
    }
    if (wipp->log != NULL) {
        CALL_SMETHOD(wipp->log->rcnt, decref);
    }
    free(wipp->free_ptr);
}
