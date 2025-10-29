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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"

#include "rtpp_cfg.h"
#include "rtpp_debug.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_genuid.h"
#include "rtpp_mallocs.h"
#include "rtpp_pcount.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_weakref.h"
#include "rtpp_time.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_pipe_fin.h"
#include "rtpp_ttl.h"
#include "rtpp_math.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_pcnts_strm.h"
#include "rtpp_stats.h"
#include "rtpp_refcnt.h"
#include "rtpp_session.h"
#include "advanced/pproc_manager.h"

struct rtpp_pipe_priv
{
    struct rtpp_pipe pub;
    struct rtpp_weakref *streams_wrt;
    int pipe_type;
};

static void rtpp_pipe_dtor(struct rtpp_pipe_priv *);
static int rtpp_pipe_get_ttl(struct rtpp_pipe *);
static void rtpp_pipe_decr_ttl(struct rtpp_pipe *);
static void rtpp_pipe_get_stats(struct rtpp_pipe *, struct rtpp_acct_pipe *);
static void rtpp_pipe_upd_cntrs(struct rtpp_pipe *, struct rtpp_acct_pipe *);

#define NO_MED_NM(t) (((t) == PIPE_RTP) ? "nsess_nortp" : "nsess_nortcp")
#define OW_MED_NM(t) (((t) == PIPE_RTP) ? "nsess_owrtp" : "nsess_owrtcp")

#define MT2RT_NZ(mt) ((mt).wall)
#define DRTN_NZ(bmt, emt) ((emt).mono == 0.0 || (bmt).mono == 0.0 ? 0.0 : ((emt).mono - (bmt).mono))

DEFINE_SMETHODS(rtpp_pipe,
    .get_ttl = &rtpp_pipe_get_ttl,
    .decr_ttl = &rtpp_pipe_decr_ttl,
    .get_stats = &rtpp_pipe_get_stats,
    .upd_cntrs = &rtpp_pipe_upd_cntrs,
);

struct rtpp_pipe *
rtpp_pipe_ctor(const struct r_pipe_ctor_args *ap)
{
    struct rtpp_pipe_priv *pvt;
    const struct rtpp_cfg *cfs = ap->session_cap->cfs;
    int i;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pipe_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }

    RTPP_OBJ_BORROW(&pvt->pub, ap->log);
    if (ap->pipe_type == PIPE_RTP) {
        pvt->streams_wrt = cfs->rtp_streams_wrt;
    } else {
        pvt->streams_wrt = cfs->rtcp_streams_wrt;
    }

    pvt->pub.ppuid = CALL_SMETHOD(cfs->guid, gen);
    struct r_stream_ctor_args rsca = {
        .pipe_cap = ap,
    };
    for (i = 0; i < 2; i++) {
        rsca.side = i;
        pvt->pub.stream[i] = rtpp_stream_ctor(&rsca);
        if (pvt->pub.stream[i] == NULL) {
            goto e1;
        }
        RTPP_OBJ_DTOR_ATTACH_OBJ(&pvt->pub, pvt->pub.stream[i]);
        if (CALL_SMETHOD(pvt->streams_wrt, reg, pvt->pub.stream[i]->rcnt,
          pvt->pub.stream[i]->stuid) != 0) {
            goto e1;
        }
    }
    pvt->pub.stream[0]->stuid_sendr = pvt->pub.stream[1]->stuid;
    pvt->pub.stream[1]->stuid_sendr = pvt->pub.stream[0]->stuid;
    pvt->pub.pcount = rtpp_pcount_ctor();
    if (pvt->pub.pcount == NULL) {
        goto e1;
    }
    RTPP_OBJ_DTOR_ATTACH_OBJ(&pvt->pub, pvt->pub.pcount);
    for (i = 0; i < 2; i++) {
        RTPP_OBJ_BORROW(pvt->pub.stream[i], pvt->pub.pcount);
        pvt->pub.stream[i]->pcount = pvt->pub.pcount;
    }
    pvt->pub.stream[0]->pproc_manager->reverse = pvt->pub.stream[1]->pproc_manager;
    RTPP_OBJ_BORROW(&pvt->pub, pvt->pub.stream[1]->pproc_manager);
    pvt->pub.stream[1]->pproc_manager->reverse = pvt->pub.stream[0]->pproc_manager;
    RTPP_OBJ_BORROW(&pvt->pub, pvt->pub.stream[0]->pproc_manager);
    pvt->pipe_type = ap->pipe_type;
    pvt->pub.rtpp_stats = cfs->rtpp_stats;
    pvt->pub.log = ap->log;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_pipe_dtor);
#if defined(RTPP_DEBUG)
    RTPP_OBJ_DTOR_ATTACH(&pvt->pub, rtpp_pipe_fin, &(pvt->pub));
#endif
    return (&pvt->pub);

e1:
    for (i = 0; i < 2; i++)
        if (pvt->pub.stream[i] != NULL)
            CALL_SMETHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
rtpp_pipe_dtor(struct rtpp_pipe_priv *pvt)
{
    int i;

    for (i = 0; i < 2; i++) {
        CALL_SMETHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
    }
}

static int
rtpp_pipe_get_ttl(struct rtpp_pipe *self)
{
    int ttls[2];

    ttls[0] = CALL_SMETHOD(self->stream[0]->ttl, get_remaining);
    ttls[1] = CALL_SMETHOD(self->stream[1]->ttl, get_remaining);
    return (MIN(ttls[0], ttls[1]));
}

static void
rtpp_pipe_decr_ttl(struct rtpp_pipe *self)
{
    CALL_SMETHOD(self->stream[0]->ttl, decr);
    if (self->stream[1]->ttl == self->stream[0]->ttl)
        return;
    CALL_SMETHOD(self->stream[1]->ttl, decr);
}

static void
rtpp_pipe_get_stats(struct rtpp_pipe *self, struct rtpp_acct_pipe *rapp)
{
    struct rtpp_pipe_priv *pvt;

    PUB2PVT(self, pvt);

    CALL_SMETHOD(self->pcount, get_stats, rapp->pcnts);
    CALL_SMETHOD(self->stream[0], get_stats, &rapp->o.hld_stat);
    CALL_SMETHOD(self->stream[1], get_stats, &rapp->a.hld_stat);
    CALL_SMETHOD(self->stream[0]->pcnt_strm, get_stats, rapp->o.ps);
    CALL_SMETHOD(self->stream[1]->pcnt_strm, get_stats, rapp->a.ps);
    rapp->o.rem_addr = CALL_SMETHOD(self->stream[0], get_rem_addr, 1);
    rapp->a.rem_addr = CALL_SMETHOD(self->stream[1], get_rem_addr, 1);
    RTPP_LOG(self->log, RTPP_LOG_INFO, "%s stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored",
      PP_NAME(pvt->pipe_type), rapp->o.ps->npkts_in,
      rapp->a.ps->npkts_in, rapp->pcnts->nrelayed, rapp->pcnts->ndropped,
      rapp->pcnts->nignored);
    if (rapp->pcnts->ndropped > 0) {
        CALL_SMETHOD(self->pcount, log_drops, self->log);
    }
    if (pvt->pipe_type != PIPE_RTP) {
        return;
    }
    if (rapp->o.ps->first_pkt_rcv.mono > 0.0) {
        RTPP_LOG(self->log, RTPP_LOG_INFO, "RTP times: caller: first in at %f, "
          "duration %f, longest IPI %f", MT2RT_NZ(rapp->o.ps->first_pkt_rcv),
          DRTN_NZ(rapp->o.ps->first_pkt_rcv, rapp->o.ps->last_pkt_rcv),
          rapp->o.ps->longest_ipi);
    }
    if (rapp->a.ps->first_pkt_rcv.mono > 0.0) {
        RTPP_LOG(self->log, RTPP_LOG_INFO, "RTP times: callee: first in at %f, "
          "duration %f, longest IPI %f", MT2RT_NZ(rapp->a.ps->first_pkt_rcv),
          DRTN_NZ(rapp->a.ps->first_pkt_rcv, rapp->a.ps->last_pkt_rcv),
          rapp->a.ps->longest_ipi);
    }

}

static void
rtpp_pipe_upd_cntrs(struct rtpp_pipe *self, struct rtpp_acct_pipe *rapp)
{
    struct rtpp_pipe_priv *pvt;

    PUB2PVT(self, pvt);

    if (rapp->o.ps->npkts_in == 0 && rapp->a.ps->npkts_in == 0) {
        CALL_SMETHOD(self->rtpp_stats, updatebyname, NO_MED_NM(pvt->pipe_type),
          1);
    } else if (rapp->o.ps->npkts_in == 0 || rapp->a.ps->npkts_in == 0) {
        CALL_SMETHOD(self->rtpp_stats, updatebyname, OW_MED_NM(pvt->pipe_type),
          1);
    }
}
