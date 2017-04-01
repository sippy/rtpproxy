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

#include "rtpp_genuid_singlet.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_pcount.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_weakref.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_ttl.h"
#include "rtpp_math.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_stats.h"
#include "rtpp_monotime.h"

struct rtpp_pipe_priv
{
    struct rtpp_pipe pub;
    struct rtpp_weakref_obj *streams_wrt;
    int pipe_type;
};

#define PUB2PVT(pubp)      ((struct rtpp_pipe_priv *)((char *)(pubp) - offsetof(struct rtpp_pipe_priv, pub)))

static void rtpp_pipe_dtor(struct rtpp_pipe_priv *);
static int rtpp_pipe_get_ttl(struct rtpp_pipe *);
static void rtpp_pipe_decr_ttl(struct rtpp_pipe *);
static void rtpp_pipe_get_stats(struct rtpp_pipe *, struct rtpp_acct_pipe *);
static void rtpp_pipe_upd_cntrs(struct rtpp_pipe *, struct rtpp_acct_pipe *);

#define NO_MED_NM(t) (((t) == PIPE_RTP) ? "nsess_nortp" : "nsess_nortcp")
#define OW_MED_NM(t) (((t) == PIPE_RTP) ? "nsess_owrtp" : "nsess_owrtcp")

#define MT2RT_NZ(mt) ((mt) == 0.0 ? 0.0 : dtime2rtime(mt))
#define DRTN_NZ(bmt, emt) ((emt) == 0.0 || (bmt) == 0.0 ? 0.0 : ((emt) - (bmt)))

struct rtpp_pipe *
rtpp_pipe_ctor(uint64_t seuid, struct rtpp_weakref_obj *streams_wrt,
  struct rtpp_weakref_obj *servers_wrt, struct rtpp_log *log,
  struct rtpp_stats *rtpp_stats, int pipe_type)
{
    struct rtpp_pipe_priv *pvt;
    struct rtpp_refcnt *rcnt;
    int i;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pipe_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;

    pvt->streams_wrt = streams_wrt;

    rtpp_gen_uid(&pvt->pub.ppuid);
    for (i = 0; i < 2; i++) {
        pvt->pub.stream[i] = rtpp_stream_ctor(log, servers_wrt,
          rtpp_stats, i, pipe_type, seuid);
        if (pvt->pub.stream[i] == NULL) {
            goto e1;
        }
        if (CALL_METHOD(pvt->streams_wrt, reg, pvt->pub.stream[i]->rcnt,
          pvt->pub.stream[i]->stuid) != 0) {
            goto e1;
        }
    }
    pvt->pub.stream[0]->stuid_sendr = pvt->pub.stream[1]->stuid;
    pvt->pub.stream[1]->stuid_sendr = pvt->pub.stream[0]->stuid;
    pvt->pub.pcount = rtpp_pcount_ctor();
    if (pvt->pub.pcount == NULL) {
        goto e2;
    }
    for (i = 0; i < 2; i++) {
        CALL_SMETHOD(pvt->pub.pcount->rcnt, incref);
        pvt->pub.stream[i]->pcount = pvt->pub.pcount;
    }
    pvt->pipe_type = pipe_type;
    pvt->pub.rtpp_stats = rtpp_stats;
    pvt->pub.log = log;
    pvt->pub.get_ttl = &rtpp_pipe_get_ttl;
    pvt->pub.decr_ttl = &rtpp_pipe_decr_ttl;
    pvt->pub.get_stats = &rtpp_pipe_get_stats;
    pvt->pub.upd_cntrs = &rtpp_pipe_upd_cntrs;
    CALL_SMETHOD(log->rcnt, incref);
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pipe_dtor, pvt);
    return (&pvt->pub);

e2:
e1:
    for (i = 0; i < 2; i++) {
        if (pvt->pub.stream[i] != NULL) {
            CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
            CALL_SMETHOD(pvt->pub.stream[i]->rcnt, decref);
        }
    }
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_pipe_dtor(struct rtpp_pipe_priv *pvt)
{
    int i;

    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
        CALL_SMETHOD(pvt->pub.stream[i]->rcnt, decref);
    }
    CALL_SMETHOD(pvt->pub.pcount->rcnt, decref);
    CALL_SMETHOD(pvt->pub.log->rcnt, decref);
    free(pvt);
}

static int
rtpp_pipe_get_ttl(struct rtpp_pipe *self)
{
    int ttls[2];

    ttls[0] = CALL_METHOD(self->stream[0]->ttl, get_remaining);
    ttls[1] = CALL_METHOD(self->stream[1]->ttl, get_remaining);
    return (MIN(ttls[0], ttls[1]));
}

static void
rtpp_pipe_decr_ttl(struct rtpp_pipe *self)
{
    CALL_METHOD(self->stream[0]->ttl, decr);
    if (self->stream[1]->ttl == self->stream[0]->ttl)
        return;
    CALL_METHOD(self->stream[1]->ttl, decr);
}

static void
rtpp_pipe_get_stats(struct rtpp_pipe *self, struct rtpp_acct_pipe *rapp)
{
    struct rtpp_pipe_priv *pvt;

    pvt = PUB2PVT(self);

    CALL_METHOD(self->pcount, get_stats, rapp->pcnts);
    CALL_SMETHOD(self->stream[0], get_stats, &rapp->o.hld_stat);
    CALL_SMETHOD(self->stream[1], get_stats, &rapp->a.hld_stat);
    CALL_METHOD(self->stream[0]->pcnt_strm, get_stats, rapp->o.ps);
    CALL_METHOD(self->stream[1]->pcnt_strm, get_stats, rapp->a.ps);
    rapp->o.rem_addr = CALL_SMETHOD(self->stream[0], get_rem_addr, 1);
    rapp->a.rem_addr = CALL_SMETHOD(self->stream[1], get_rem_addr, 1);
    RTPP_LOG(self->log, RTPP_LOG_INFO, "%s stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored",
      PP_NAME(pvt->pipe_type), rapp->o.ps->npkts_in,
      rapp->a.ps->npkts_in, rapp->pcnts->nrelayed, rapp->pcnts->ndropped,
      rapp->pcnts->nignored);
    if (pvt->pipe_type != PIPE_RTP) {
        return;
    }
    if (rapp->o.ps->first_pkt_rcv > 0.0) {
        RTPP_LOG(self->log, RTPP_LOG_INFO, "RTP times: caller: first in at %f, "
          "duration %f, longest IPI %f", MT2RT_NZ(rapp->o.ps->first_pkt_rcv),
          DRTN_NZ(rapp->o.ps->first_pkt_rcv, rapp->o.ps->last_pkt_rcv),
          rapp->o.ps->longest_ipi);
    }
    if (rapp->a.ps->first_pkt_rcv > 0.0) {
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

    pvt = PUB2PVT(self);

    if (rapp->o.ps->npkts_in == 0 && rapp->a.ps->npkts_in == 0) {
        CALL_METHOD(self->rtpp_stats, updatebyname, NO_MED_NM(pvt->pipe_type),
          1);
    } else if (rapp->o.ps->npkts_in == 0 || rapp->a.ps->npkts_in == 0) {
        CALL_METHOD(self->rtpp_stats, updatebyname, OW_MED_NM(pvt->pipe_type),
          1);
    }
}
