/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2024 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_str.h"
#include "rtpp_time.h"
#include "rtpp_command_stats.h"
#include "rtpp_command_ctx.h"
#include "rtpp_command_rcache.h"
#include "rtpp_network.h"
#include "rtpp_netio_async.h"
#include "rtpp_proc_async.h"
#include "rtpp_command_reply.h"

struct rtpc_reply_priv {
    struct rtpc_reply pub;
    const struct rtpp_command_ctx *ctx;
    struct {
        int ulen;
        int clen;
        int rlen;
        char r[1024];
    } buf;
};

static void rtpc_reply_deliver_error(struct rtpc_reply *, int);
static void rtpc_reply_deliver_ok(struct rtpc_reply *);
static void rtpc_reply_deliver_number(struct rtpc_reply *, int);
static int rtpc_reply_append_port_addr(struct rtpc_reply *, const struct sockaddr *,
  int);
static int rtpc_reply_deliver_port_addr(struct rtpc_reply *, const struct sockaddr *,
  int);
static int rtpc_reply_append_port_addr_s(struct rtpc_reply *, const char *,
  int, int);
static void rtpc_reply_deliver(struct rtpc_reply *, int);
static int rtpc_reply_append(struct rtpc_reply *, const char *, int, int);
static int rtpc_reply_appendf(struct rtpc_reply *, const char *, ...)
  __attribute__ ((format (printf, 2, 3)));
static void rtpc_reply_commit(struct rtpc_reply *);
static int rtpc_reply_reserve(struct rtpc_reply *, int);

DEFINE_SMETHODS(rtpc_reply,
    .deliver_error = &rtpc_reply_deliver_error,
    .deliver_ok = &rtpc_reply_deliver_ok,
    .deliver_number = &rtpc_reply_deliver_number,
    .deliver_port_addr = &rtpc_reply_deliver_port_addr,
    .append_port_addr = &rtpc_reply_append_port_addr,
    .append_port_addr_s = &rtpc_reply_append_port_addr_s,
    .deliver = &rtpc_reply_deliver,
    .append = &rtpc_reply_append,
    .appendf = &rtpc_reply_appendf,
    .commit = &rtpc_reply_commit,
    .reserve = &rtpc_reply_reserve,
);

#define CBP(pvt) ((pvt)->buf.r + (pvt)->buf.ulen)
#define CBL(pvt) ((pvt)->buf.ulen)
#define CBRL(pvt, fin) (sizeof(pvt->buf.r) - (pvt)->buf.ulen - \
  ((fin) ? 0 : (pvt)->buf.rlen))
#define CBP_C(pvt) ((pvt)->buf.r + (pvt)->buf.clen)
#define CBL_C(pvt) ((pvt)->buf.clen)

struct rtpc_reply *
rtpc_reply_ctor(const struct rtpp_command_ctx *ctx)
{
    struct rtpc_reply_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpc_reply_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }

    pvt->ctx = ctx;
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = rtpc_reply_smethods;
#endif
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpc_reply_deliver(struct rtpc_reply *self, int errd)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);

    if (CBL_C(pvt) > 0 && CBP_C(pvt)[-1] == '\n') {
        RTPP_LOG(pvt->ctx->cfs->glog, RTPP_LOG_DBUG, "sending reply \"%.*s\\n\"",
          pvt->buf.clen - 1, pvt->buf.r);
    } else {
        RTPP_LOG(pvt->ctx->cfs->glog, RTPP_LOG_DBUG, "sending reply \"%.*s\"",
          pvt->buf.clen, pvt->buf.r);
    }
    if (pvt->ctx->umode == 0) {
        if (write(pvt->ctx->controlfd, pvt->buf.r, pvt->buf.clen) < 0) {
            RTPP_DBG_ASSERT(!IS_WEIRD_ERRNO(errno));
        }
    } else {
        if (pvt->ctx->cookie.s != NULL) {
            rtpp_str_t c = {.s=pvt->buf.r, .len=pvt->buf.clen};
            CALL_METHOD(pvt->ctx->rcache_obj, insert, rtpp_str_fix(&pvt->ctx->cookie), &c,
              self->rcnt, pvt->ctx->dtime.mono);
        }
        RTPP_OBJ_INCREF(self);
        if (rtpp_anetio_sendto_na(pvt->ctx->cfs->rtpp_proc_cf->netio, pvt->ctx->controlfd,
          pvt->buf.r, pvt->buf.clen, 0, sstosa(&pvt->ctx->raddr), pvt->ctx->rlen,
          self->rcnt) != 0)
        {
            RTPP_OBJ_DECREF(self);
        }
    }
    pvt->ctx->csp->ncmds_repld.cnt++;
    if (errd == 0) {
        pvt->ctx->csp->ncmds_succd.cnt++;
    } else {
        pvt->ctx->csp->ncmds_errs.cnt++;
    }
}

static void
rtpc_reply_deliver_number(struct rtpc_reply *self, int number)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    pvt->buf.ulen = pvt->buf.clen;
    assert(rtpc_reply_appendf(self, "%d\n", number) == 0);
    pvt->buf.clen = pvt->buf.ulen;
    rtpc_reply_deliver(self, 0);
}

static int
rtpc_reply_append_port_addr_s(struct rtpc_reply *self, const char *sap, int port, int pf)
{
    const char *at = pf == AF_INET ? "" : " 6";

    return rtpc_reply_appendf(self, "%d %s%s", port, sap, at);
}

static int
rtpc_reply_append_port_addr(struct rtpc_reply *self, const struct sockaddr *sa, int port)
{
    char saddr[MAX_ADDR_STRLEN];

    addr2char_r(sa, saddr, sizeof(saddr));
    return rtpc_reply_append_port_addr_s(self, saddr, port, sa->sa_family);
}

static int
rtpc_reply_deliver_port_addr(struct rtpc_reply *self, const struct sockaddr *sa, int port)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    int r;

    r = rtpc_reply_append_port_addr(self, sa, port);
    if (r != 0)
        return (r);
    r = rtpc_reply_append(self, "\n", 2, 1);
    if (r != 0)
        return (r);
    rtpc_reply_commit(self);
    rtpc_reply_deliver(self, 0);
    return (0);
}

static void
rtpc_reply_deliver_ok(struct rtpc_reply *self)
{

    rtpc_reply_deliver_number(self, 0);
}

static void
rtpc_reply_deliver_error(struct rtpc_reply *self, int ecode)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    pvt->buf.ulen = pvt->buf.clen;
    assert(rtpc_reply_appendf(self, "E%d\n", ecode) == 0);
    pvt->buf.clen = pvt->buf.ulen;
    rtpc_reply_deliver(self, 1);
}

static int
rtpc_reply_append(struct rtpc_reply *self, const char *buf, int len, int final)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    if (CBRL(pvt, final) < len) {
        RTPP_LOG(pvt->ctx->cfs->glog, RTPP_LOG_ERR, "reply buffer overflow");
        return (-1);
    }
    memcpy(CBP(pvt), buf, len);
    if (buf[len - 1] == '\0')
        len--;
    pvt->buf.ulen += len;
    return (0);
}

static int
rtpc_reply_appendf(struct rtpc_reply *self, const char *fmt, ...)
{
    struct rtpc_reply_priv *pvt;
    va_list ap;
    int plen;

    PUB2PVT(self, pvt);
    va_start(ap, fmt);
    plen = vsnprintf(CBP(pvt), CBRL(pvt, 0), fmt, ap);
    va_end(ap);
    if (plen >= CBRL(pvt, 0)) {
        RTPP_LOG(pvt->ctx->cfs->glog, RTPP_LOG_ERR, "reply buffer overflow");
        return (-1);
    }
    pvt->buf.ulen += plen;
    return (0);
}

void
rtpc_reply_commit(struct rtpc_reply *self)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    RTPP_DBG_ASSERT(pvt->buf.ulen >= pvt->buf.clen);
    pvt->buf.clen = pvt->buf.ulen;
}

int
rtpc_reply_reserve(struct rtpc_reply *self, int rlen)
{
    struct rtpc_reply_priv *pvt;

    PUB2PVT(self, pvt);
    if (CBRL(pvt, 1) < rlen)
        return (-1);
    pvt->buf.rlen = rlen;
    return (0);
}
