/*
 * Copyright (c) 2006-2018 Sippy Software, Inc., http://www.sippysoft.com
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

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_module.h"
#include "rtpp_module_acct.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg.h"
#include "rtpp_acct_rtcp.h"
#include "rtpp_network.h"
#include "rtpp_time.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_ssrc.h"
#include "ucl.h"
#include "rtpp_ucl.h"
#include "rtpa_stats.h"
#include "rtpp_linker_set.h"
#include "rtpp_refcnt.h"

#include "rtcp2json.h"
#include "core_hep.h"
#include "hep_api.h"
#include "hepconnector.h"
#include "rtpp_sbuf.h"

#include "_acct_rtcp_hep_config.h"

struct rtpp_module_priv {
   struct rtpp_sbuf *sbp;
   struct hep_ctx *ctx;
   struct rtpp_minfo *mself;
};

static struct rtpp_module_priv *rtpp_acct_rtcp_hep_ctor(const struct rtpp_cfg *,
  struct rtpp_minfo *);
static void rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *);
static void rtpp_acct_rtcp_hep_do(struct rtpp_module_priv *, struct rtpp_acct_rtcp *);
static struct rtpp_module_conf *rtpp_acct_rtcp_hep_get_mconf(void);
static int rtpp_acct_rtcp_hep_config(struct rtpp_module_priv *,
  struct rtpp_module_conf *);

extern const struct rtpp_module_conf _rtpp_arh_conf;

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

static const struct rtpp_acct_handlers acct_rtcp_hep_aapi = {
    .on_rtcp_rcvd = AAPI_FUNC(rtpp_acct_rtcp_hep_do, rtpp_acct_rtcp_OSIZE())
};

const struct rtpp_minfo RTPP_MOD_SELF = {
    .descr.name = "acct_rtcp_hep",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 2,
    .proc.ctor = rtpp_acct_rtcp_hep_ctor,
    .proc.dtor = rtpp_acct_rtcp_hep_dtor,
    .proc.get_mconf = rtpp_acct_rtcp_hep_get_mconf,
    .proc.config = rtpp_acct_rtcp_hep_config,
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM,
#endif
    .aapi = &acct_rtcp_hep_aapi,
    .fn = &(struct rtpp_minfo_fset){0},
};
#if defined(LIBRTPPROXY)
DATA_SET(rtpp_modules, RTPP_MOD_SELF);
#endif

static struct rtpp_module_priv *
rtpp_acct_rtcp_hep_ctor(const struct rtpp_cfg *cfsp, struct rtpp_minfo *mself)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->sbp = rtpp_sbuf_ctor(512);
    if (pvt->sbp == NULL) {
        goto e1;
    }
    pvt->mself = mself;
    return (pvt);

#if 0
e2:
    rtpp_sbuf_dtor(pvt->sbp);
#endif
e1:
    mod_free(pvt);
e0:
    return (NULL);
}

struct rtpp_module_conf_pvt {
    struct hep_ctx ctx;
    struct rtpp_module_conf pub;
};

static int
rtpp_acct_rtcp_hep_config(struct rtpp_module_priv *pvt,
  struct rtpp_module_conf *mcpub)
{
    struct rtpp_module_conf_pvt *mcpvt;
    PUB2PVT(mcpub, mcpvt);
    pvt->ctx = &mcpvt->ctx;
    if (init_hepsocket(pvt->ctx) != 0) {
        return (-1);
    }
    return (0);
}

static void
rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *pvt)
{
    hep_gen_dtor(pvt->ctx);
    rtpp_sbuf_dtor(pvt->sbp);
    mod_free(pvt);
    return;
}

static void
rtpp_acct_rtcp_hep_do(struct rtpp_module_priv *pvt, struct rtpp_acct_rtcp *rarp)
{
    struct rc_info ri;
    const struct sockaddr *src_addr, *dst_addr;
    struct timeval rtimeval;
    int rval;

    memset(&ri, '\0', sizeof(ri));

    src_addr = sstosa(&(rarp->pkt->raddr));
    dst_addr = rarp->pkt->laddr;
    ri.ip_proto = 17; /* UDP */
    ri.proto_type = 5; /* RTCP */

    ri.ip_family = dst_addr->sa_family;
    switch (ri.ip_family) {
    case AF_INET:
        ri.src.p4 = &(satosin(src_addr)->sin_addr);
        ri.dst.p4 = &(satosin(dst_addr)->sin_addr);
        break;

    case AF_INET6:
        ri.src.p6 = &(satosin6(src_addr)->sin6_addr);
        ri.dst.p6 = &(satosin6(dst_addr)->sin6_addr);
        break;

    default:
        abort();
    }

    ri.src_port = getport(src_addr);
    ri.dst_port = rarp->pkt->lport;
    dtime2timeval(rarp->pkt->rtime.wall, &rtimeval);
    ri.time_sec = SEC(&rtimeval);
    ri.time_usec = USEC(&rtimeval);
    if (hep_gen_fill(pvt->ctx, &ri) < 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "hep_gen_fill() failed");
        goto out;
    }

    if (hep_gen_append(pvt->ctx, HEP_VID_GEN, HEP_TID_CID, rarp->call_id,
      strlen(rarp->call_id)) < 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "hep_gen_append() failed");
        goto out;
    }

    rtpp_sbuf_reset(pvt->sbp);
    rval = rtcp2json(pvt->sbp, rarp->pkt->data.buf, rarp->pkt->size);
    if (rval < 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "rtcp2json() failed: %d", rval);
        goto out;
    }

    rval = send_hep(pvt->ctx, &ri, pvt->sbp->bp, RS_ULEN(pvt->sbp));
    if (rval < 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_INFO, "send_hep() failed: %d", rval);
    }

out:
    return;
}

static void
mconf_dtor(struct hep_ctx *ctxp)
{
    if (ctxp->capt_host != NULL && ctxp->capt_host != default_ctx.capt_host) {
        mod_free(ctxp->capt_host);
    }
}

static struct rtpp_module_conf *
rtpp_acct_rtcp_hep_get_mconf(void)
{
    struct rtpp_module_conf_pvt *cp;

    cp = mod_rzmalloc(sizeof(*cp), PVT_RCOFFS(cp));
    if (cp == NULL)
        return NULL;
    struct rtpp_refcnt *rtp = cp->pub.rcnt;
    cp->pub = _rtpp_arh_conf;
    cp->pub.rcnt = rtp;
    cp->ctx = default_ctx;
    cp->pub.conf_data = &cp->ctx;
    RTPP_OBJ_DTOR_ATTACH(&(cp->pub), mconf_dtor, &cp->ctx);
    return (&cp->pub);
}
