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
    struct rtpp_wi wi;
    struct sockaddr_storage to;
    char msg[0];
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
    memset(wis, '\0', sizeof(struct rtpp_wi_sendto));
    wis->wi.free_ptr = &(wis->wi);
    wis->wi.wi_type = RTPP_WI_TYPE_OPKT;
    wis->wi.sock = sock;
    wis->wi.flags = flags;
    wis->wi.msg = &(wis->msg);
    wis->wi.sendto = sstosa(&(wis->to));
    wis->wi.msg_len = msg_len;
    wis->wi.nsend = 1;
    memcpy(wis->msg, msg, msg_len);
    wis->wi.tolen = tolen;
    memcpy(&(wis->to), sendto, tolen);
    return (&(wis->wi));
}

struct rtpp_wi *
rtpp_wi_malloc_pkt(int sock, struct rtp_packet *pkt,
  const struct sockaddr *sendto, size_t tolen, int nsend,
  struct rtpp_refcnt *sock_rcnt)
{
    struct rtpp_wi *wi;

    wi = pkt->wi;
    wi->free_ptr = (struct rtpp_wi *)pkt;
    wi->wi_type = RTPP_WI_TYPE_OPKT;
    wi->sock = sock;
    if (sock_rcnt != NULL) {
        CALL_SMETHOD(sock_rcnt, incref);
    }
    wi->sock_rcnt = sock_rcnt;
    wi->flags = 0;
    wi->msg = pkt->data.buf;
    wi->msg_len = pkt->size;
    wi->sendto = sstosa(&pkt->sendto);
    wi->tolen = tolen;
    memcpy(wi->sendto, sendto, tolen);
    wi->nsend = nsend;
    return (wi);
}

struct rtpp_wi *
rtpp_wi_malloc_pkt_na(int sock, struct rtp_packet *pkt,
  struct rtpp_netaddr *sendto, int nsend,
  struct rtpp_refcnt *sock_rcnt)
{
    struct rtpp_wi *wi;

    wi = pkt->wi;
    wi->free_ptr = (struct rtpp_wi *)pkt;
    wi->wi_type = RTPP_WI_TYPE_OPKT;
    wi->sock = sock;
    if (sock_rcnt != NULL) {
        CALL_SMETHOD(sock_rcnt, incref);
    }
    wi->sock_rcnt = sock_rcnt;
    wi->flags = 0;
    wi->msg = pkt->data.buf;
    wi->msg_len = pkt->size;
    wi->sendto = sstosa(&pkt->sendto);
    wi->tolen = CALL_SMETHOD(sendto, get, wi->sendto, sizeof(pkt->raddr));
    wi->nsend = nsend;
    return (wi);
}

struct rtpp_wi *
#if !defined(RTPP_CHECK_LEAKS)
rtpp_wi_malloc_sgnl(int signum, const void *data, size_t datalen)
#else
rtpp_wi_malloc_sgnl_memdeb(const char *fname, int linen, const char *funcn, int signum, const void *data, size_t datalen)
#endif
{
    struct rtpp_wi *wi;
#if !defined(RTPP_CHECK_LEAKS)
    wi = malloc(sizeof(struct rtpp_wi) + datalen);
#else
    wi = rtpp_memdeb_malloc(sizeof(struct rtpp_wi) + datalen, MEMDEB_SYM, fname, linen, funcn);
#endif
    if (wi == NULL) {
        return (NULL);
    }
    memset(wi, '\0', sizeof(struct rtpp_wi));
    wi->free_ptr = wi;
    wi->wi_type = RTPP_WI_TYPE_SGNL;
    wi->flags = signum;
    if (datalen > 0) {
        wi->msg = wi->data;
        wi->msg_len = datalen;
        memcpy(wi->data, data, datalen);
    }
    return (wi);
}

struct rtpp_wi *
rtpp_wi_malloc_apis(const char *apiname, void *data, size_t datalen)
{
    struct rtpp_wi *wi;

    wi = malloc(sizeof(struct rtpp_wi) + datalen);
    if (wi == NULL) {
        return (NULL);
    }
    memset(wi, '\0', sizeof(struct rtpp_wi));
    wi->free_ptr = wi;
    wi->wi_type = RTPP_WI_TYPE_API_STR;
    wi->sendto = (void *)apiname;
    if (datalen > 0) {
        wi->msg = wi->data;
        wi->msg_len = datalen;
        memcpy(wi->data, data, datalen);
    }
    return (wi);
}

struct rtpp_wi *
rtpp_wi_malloc_data(void *dataptr, size_t datalen)
{
    struct rtpp_wi *wi;

    wi = malloc(sizeof(struct rtpp_wi) + datalen);
    if (wi == NULL) {
        return (NULL);
    }
    memset(wi, '\0', sizeof(struct rtpp_wi));
    wi->free_ptr = wi;
    wi->wi_type = RTPP_WI_TYPE_DATA;
    if (datalen > 0) {
        wi->msg = wi->data;
        wi->msg_len = datalen;
        memcpy(wi->data, dataptr, datalen);
    }
    return (wi);
}

struct rtpp_wi *
rtpp_wi_malloc_udata(void **dataptr, size_t datalen)
{
    struct rtpp_wi *wi;

    wi = malloc(sizeof(struct rtpp_wi) + datalen);
    if (wi == NULL) {
        return (NULL);
    }
    memset(wi, '\0', sizeof(struct rtpp_wi));
    wi->free_ptr = wi;
    wi->wi_type = RTPP_WI_TYPE_DATA;
    if (datalen > 0) {
        wi->msg = wi->data;
        wi->msg_len = datalen;
        *dataptr = wi->data;
    }
    return (wi);
}

enum rtpp_wi_type
rtpp_wi_get_type(struct rtpp_wi *wi)
{

    return (wi->wi_type);
}

void *
rtpp_wi_sgnl_get_data(struct rtpp_wi *wi, size_t *datalen)
{

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    if (datalen != NULL) {
        *datalen = wi->msg_len;
    }
    return(wi->msg);
}

int
rtpp_wi_sgnl_get_signum(struct rtpp_wi *wi)
{

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    return (wi->flags);
}

void *
rtpp_wi_data_get_ptr(struct rtpp_wi *wi, size_t min_len, size_t max_len)
{

    assert(wi->wi_type == RTPP_WI_TYPE_DATA);
    assert(wi->msg_len >= min_len);
    assert(max_len == 0 || wi->msg_len <= max_len);

    return(wi->msg);
}

const char *
rtpp_wi_apis_getname(struct rtpp_wi *wi)
{

    assert(wi->wi_type == RTPP_WI_TYPE_API_STR);
    return ((const char *)wi->sendto);
}

const char *
rtpp_wi_apis_getnamearg(struct rtpp_wi *wi, void **datap, size_t datalen)
{

    assert(wi->wi_type == RTPP_WI_TYPE_API_STR);
    assert(wi->msg_len == datalen);
    if (datap != NULL && datalen > 0) {
        memcpy(datap, wi->data, datalen);
    }
    return ((const char *)wi->sendto);
}

void
rtpp_wi_free(struct rtpp_wi *wi)
{

    if (wi->sock_rcnt != NULL) {
        CALL_SMETHOD(wi->sock_rcnt, decref);
    }
    if (wi->log != NULL) {
        CALL_SMETHOD(wi->log->rcnt, decref);
    }
    free(wi->free_ptr);
}
