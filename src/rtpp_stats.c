/*
 * Copyright (c) 2014-2015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_pearson_perfect.h"
#include "rtpp_refcnt.h"
#include "rtpp_stats.h"
#include "rtpp_stats_fin.h"
#include "rtpp_time.h"
#include "rtpp_mallocs.h"

struct rtpp_stat_derived;

enum rtpp_cnt_type {
    RTPP_CNT_U64,
    RTPP_CNT_DBL
};

struct rtpp_stat_descr
{
    const char *name;
    const char *descr;
    enum rtpp_cnt_type type;
    const char *derive_from;
};

union rtpp_stat_cnt {
    uint64_t u64;
    double d;
};

struct rtpp_stat
{
    struct rtpp_stat_descr *descr;
    pthread_mutex_t mutex;
    union rtpp_stat_cnt cnt;
};

struct rtpp_stat_derived
{
    struct rtpp_stat *derive_from;
    struct rtpp_stat *derive_to;
    double last_ts;
    union rtpp_stat_cnt last_val;
};

static struct rtpp_stat_descr default_stats[] = {
    {.name = "nsess_created",        .descr = "Number of RTP sessions created", .type = RTPP_CNT_U64},
    {.name = "nsess_destroyed",      .descr = "Number of RTP sessions destroyed", .type = RTPP_CNT_U64},
    {.name = "nsess_timeout",        .descr = "Number of RTP sessions ended due to media timeout", .type = RTPP_CNT_U64},
    {.name = "nsess_complete",       .descr = "Number of RTP sessions fully setup", .type = RTPP_CNT_U64},
    {.name = "nsess_nortp",          .descr = "Number of sessions that had no RTP neither in nor out", .type = RTPP_CNT_U64},
    {.name = "nsess_owrtp",          .descr = "Number of sessions that had one-way RTP only", .type = RTPP_CNT_U64},
    {.name = "nsess_nortcp",         .descr = "Number of sessions that had no RTCP neither in nor out", .type = RTPP_CNT_U64},
    {.name = "nsess_owrtcp",         .descr = "Number of sessions that had one-way RTCP only", .type = RTPP_CNT_U64}, 
    {.name = "nplrs_created",        .descr = "Number of RTP players created", .type = RTPP_CNT_U64},
    {.name = "nplrs_destroyed",      .descr = "Number of RTP players destroyed", .type = RTPP_CNT_U64},
    {.name = "npkts_rcvd",           .descr = "Total number of RTP/RTPC packets received", .type = RTPP_CNT_U64},
    {.name = "npkts_played",         .descr = "Total number of RTP packets locally generated (played out)", .type = RTPP_CNT_U64},
    {.name = "npkts_relayed",        .descr = "Total number of RTP/RTPC packets relayed", .type = RTPP_CNT_U64},
    {.name = "npkts_resizer_in",     .descr = "Total number of RTP packets ingress into resizer (re-packetizer)", .type = RTPP_CNT_U64},
    {.name = "npkts_resizer_out",    .descr = "Total number of RTP packets egress out of resizer (re-packetizer)", .type = RTPP_CNT_U64},
    {.name = "npkts_resizer_discard",.descr = "Total number of RTP packets dropped by the resizer (re-packetizer)", .type = RTPP_CNT_U64},
    {.name = "npkts_discard",        .descr = "Total number of RTP/RTPC packets discarded", .type = RTPP_CNT_U64},
    {.name = "total_duration",       .descr = "Cumulative duration of all sessions", .type = RTPP_CNT_DBL},
    {.name = "ncmds_rcvd",           .descr = "Total number of control commands received", .type = RTPP_CNT_U64},
    {.name = "ncmds_rcvd_ndups",     .descr = "Total number of duplicate control commands received", .type = RTPP_CNT_U64},
    {.name = "ncmds_succd",          .descr = "Total number of control commands successfully processed", .type = RTPP_CNT_U64},
    {.name = "ncmds_errs",           .descr = "Total number of control commands ended up with an error", .type = RTPP_CNT_U64},
    {.name = "ncmds_repld",          .descr = "Total number of control commands that had a reply generated", .type = RTPP_CNT_U64},
    {.name = "rtpa_nsent",           .descr = "Total number of uniqie RTP packets sent to us based on SEQ tracking", .type = RTPP_CNT_U64},
    {.name = "rtpa_nrcvd",           .descr = "Total number of unique RTP packets received by us based on SEQ tracking", .type = RTPP_CNT_U64},
    {.name = "rtpa_ndups",           .descr = "Total number of duplicate RTP packets received by us based on SEQ tracking", .type = RTPP_CNT_U64},
    {.name = "rtpa_perrs",           .descr = "Total number of RTP packets that failed RTP parse routine in SEQ tracking", .type = RTPP_CNT_U64},
    {.name = "pps_in",               .descr = "Rate at which RTP/RTPC packets are received (packets per second)", .type = RTPP_CNT_DBL, .derive_from = "npkts_rcvd"},
    {.name = NULL}
};

struct rtpp_stats_priv
{
    int nstats;
    int nstats_derived;
    struct rtpp_stat *stats;
    struct rtpp_stat_derived *dstats;
    struct rtpp_pearson_perfect *rppp;
};

struct rtpp_stats_full
{
    struct rtpp_stats pub;
    struct rtpp_stats_priv pvt;
};

static void rtpp_stats_dtor(struct rtpp_stats_full *);
static int rtpp_stats_getidxbyname(struct rtpp_stats *, const char *);
static int rtpp_stats_updatebyidx(struct rtpp_stats *, int, uint64_t);
static int rtpp_stats_updatebyname(struct rtpp_stats *, const char *, uint64_t);
static int rtpp_stats_updatebyname_d(struct rtpp_stats *, const char *, double);
static int64_t rtpp_stats_getlvalbyname(struct rtpp_stats *, const char *);
static int rtpp_stats_nstr(struct rtpp_stats *, char *, int, const char *);
static int rtpp_stats_getnstats(struct rtpp_stats *);
static void rtpp_stats_update_derived(struct rtpp_stats *, double);

const struct rtpp_stats_smethods rtpp_stats_smethods = {
    .getidxbyname = &rtpp_stats_getidxbyname,
    .updatebyidx = &rtpp_stats_updatebyidx,
    .updatebyname = &rtpp_stats_updatebyname,
    .updatebyname_d = &rtpp_stats_updatebyname_d,
    .getlvalbyname = &rtpp_stats_getlvalbyname,
    .getnstats = &rtpp_stats_getnstats,
    .nstr = &rtpp_stats_nstr,
    .update_derived = &rtpp_stats_update_derived
};

static const char *
getdstat(void *p, int n)
{
    struct rtpp_stats_priv *pvt;

    pvt = (struct rtpp_stats_priv *)p;
    if (n >= pvt->nstats) {
        return (NULL);
    }

    return (pvt->stats[n].descr->name);
}

static int
count_rtpp_stats(struct rtpp_stat_descr *sp)
{
    int nstats, i;

    nstats = 0;
    for (i = 0; sp[i].name != NULL; i++) {
        nstats += 1;
    }
    return (nstats);
}

static int
count_rtpp_stats_derived(struct rtpp_stat_descr *sp)
{
    int nstats, i;

    nstats = 0;
    for (i = 0; sp[i].name != NULL; i++) {
        if (sp[i].derive_from == NULL)
            continue;
        nstats += 1;
    }
    return (nstats);
}

struct rtpp_stats *
rtpp_stats_ctor(void)
{
    struct rtpp_stats_full *fp;
    struct rtpp_stats *pub;
    struct rtpp_stats_priv *pvt;
    struct rtpp_stat *st;
    struct rtpp_stat_derived *dst;
    int i, idx;

    fp = rtpp_rzmalloc(sizeof(struct rtpp_stats_full), PVT_RCOFFS(fp));
    if (fp == NULL) {
        goto e0;
    }
    pub = &(fp->pub);
    pvt = &(fp->pvt);
    pvt->stats = rtpp_zmalloc(sizeof(struct rtpp_stat) *
      count_rtpp_stats(default_stats));
    if (pvt->stats == NULL) {
        goto e1;
    }
    i = count_rtpp_stats_derived(default_stats);
    if (i > 0) {
        pvt->dstats = rtpp_zmalloc(sizeof(struct rtpp_stat_derived) * i);
        if (pvt->dstats == NULL)
            goto e2;
    }
    for (i = 0; default_stats[i].name != NULL; i++) {
        st = &pvt->stats[pvt->nstats];
        st->descr = &default_stats[i];
        if (pthread_mutex_init(&st->mutex, NULL) != 0) {
            while ((pvt->nstats - 1) >= 0) {
                st = &pvt->stats[pvt->nstats - 1];
                pthread_mutex_destroy(&st->mutex);
                pvt->nstats -= 1;
            }
            goto e2;
        }
        if (default_stats[i].type == RTPP_CNT_U64) {
            st->cnt.u64 = 0;
        } else {
            st->cnt.d = 0.0;
        }
        pvt->nstats += 1;
    }
    pvt->rppp = rtpp_pearson_perfect_ctor(getdstat, pvt);
    if (pvt->rppp == NULL) {
        goto e2;
    }
    pub->pvt = pvt;
    for (i = 0; default_stats[i].name != NULL; i++) {
        if (default_stats[i].derive_from == NULL)
            continue;
        dst = &pvt->dstats[pvt->nstats_derived];
        idx = rtpp_stats_getidxbyname(pub, default_stats[i].name);
        dst->derive_to = &pvt->stats[idx];
        idx = rtpp_stats_getidxbyname(pub, default_stats[i].derive_from);
        dst->derive_from = &pvt->stats[idx];
        pvt->nstats_derived += 1;
        dst->last_ts = getdtime();
    }
    pub->smethods = &rtpp_stats_smethods;
    CALL_SMETHOD(pub->rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_stats_dtor,
      fp);
    return (pub);
e2:
    if (pvt->dstats != NULL)
        free(pvt->dstats);
    free(pvt->stats);
e1:
    CALL_SMETHOD(pub->rcnt, decref);
    free(fp);
e0:
    return (NULL);
}

static int
rtpp_stats_getidxbyname(struct rtpp_stats *self, const char *name)
{
    struct rtpp_stats_priv *pvt;

    pvt = self->pvt;
    return (CALL_SMETHOD(pvt->rppp, hash, name));
}

static int
rtpp_stats_updatebyidx_internal(struct rtpp_stats *self, int idx,
  enum rtpp_cnt_type type, void *argp)
{
    struct rtpp_stats_priv *pvt;
    struct rtpp_stat *st;

    pvt = self->pvt;
    if (idx < 0 || idx >= pvt->nstats)
        return (-1);
    st = &pvt->stats[idx];
    pthread_mutex_lock(&st->mutex);
    if (type == RTPP_CNT_U64) {
        st->cnt.u64 += *(uint64_t *)argp;
    } else {
        st->cnt.d += *(double *)argp;
    }
    pthread_mutex_unlock(&st->mutex);
    return (0);
}

static int
rtpp_stats_updatebyidx(struct rtpp_stats *self, int idx, uint64_t incr)
{

    return rtpp_stats_updatebyidx_internal(self, idx, RTPP_CNT_U64, &incr);
}

static int
rtpp_stats_updatebyname(struct rtpp_stats *self, const char *name, uint64_t incr)
{
    int idx;

    idx = rtpp_stats_getidxbyname(self, name);
    return rtpp_stats_updatebyidx_internal(self, idx, RTPP_CNT_U64, &incr);
}

static int
rtpp_stats_updatebyname_d(struct rtpp_stats *self, const char *name, double incr)
{
    int idx;

    idx = rtpp_stats_getidxbyname(self, name);
    return rtpp_stats_updatebyidx_internal(self, idx, RTPP_CNT_DBL, &incr);
}

static int64_t
rtpp_stats_getlvalbyname(struct rtpp_stats *self, const char *name)
{
    struct rtpp_stats_priv *pvt;
    struct rtpp_stat *st;
    uint64_t rval;
    int idx;

    idx = rtpp_stats_getidxbyname(self, name);
    if (idx < 0) {
        return (-1);
    }
    pvt = self->pvt;
    st = &pvt->stats[idx];
    pthread_mutex_lock(&st->mutex);
    rval = st->cnt.u64;
    pthread_mutex_unlock(&st->mutex);
    return (rval);
}

static int
rtpp_stats_nstr(struct rtpp_stats *self, char *buf, int len, const char *name)
{
    struct rtpp_stats_priv *pvt;
    struct rtpp_stat *st;
    int idx, rval;
    uint64_t uval;
    double dval;

    idx = rtpp_stats_getidxbyname(self, name);
    if (idx < 0) {
        return (-1);
    }
    pvt = self->pvt;
    st = &pvt->stats[idx];
    if (pvt->stats[idx].descr->type == RTPP_CNT_U64) {
        pthread_mutex_lock(&st->mutex);
        uval = st->cnt.u64;
        pthread_mutex_unlock(&st->mutex);
        rval = snprintf(buf, len, "%" PRIu64, uval);
    } else {
        pthread_mutex_lock(&st->mutex);
        dval = st->cnt.d;
        pthread_mutex_unlock(&st->mutex);
        rval = snprintf(buf, len, "%f", dval);
    }
    return (rval);
}

static void
rtpp_stats_dtor(struct rtpp_stats_full *fp)
{
    int i;
    struct rtpp_stats_priv *pvt;
    struct rtpp_stat *st;

    pvt = &fp->pvt;
    for (i = 0; i < pvt->nstats; i++) {
        st = &pvt->stats[i];
        pthread_mutex_destroy(&st->mutex);
    }
    CALL_SMETHOD(pvt->rppp->rcnt, decref);
    if (pvt->dstats != NULL) {
        free(pvt->dstats);
    }
    free(pvt->stats);
    rtpp_stats_fin(&fp->pub);
    free(fp);
}

static int
rtpp_stats_getnstats(struct rtpp_stats *self)
{

    return (self->pvt->nstats);
}

static void
rtpp_stats_update_derived(struct rtpp_stats *self, double dtime)
{
    struct rtpp_stats_priv *pvt;
    int i;
    struct rtpp_stat_derived *dst;
    double ival, dval;
    union rtpp_stat_cnt last_val;

    pvt = self->pvt;
    for (i = 0; i < pvt->nstats_derived; i++) {
        dst = &pvt->dstats[i];
        assert(dst->last_ts < dtime);
        ival = dtime - dst->last_ts;
        last_val = dst->last_val;
        pthread_mutex_lock(&dst->derive_from->mutex);
        dst->last_val = dst->derive_from->cnt;
        pthread_mutex_unlock(&dst->derive_from->mutex);
        if (dst->derive_from->descr->type == RTPP_CNT_U64) {
            dval = (dst->last_val.u64 - last_val.u64) / ival;
        } else {
            dval = (dst->last_val.d - last_val.d) / ival;
        }
        pthread_mutex_lock(&dst->derive_to->mutex);
        dst->derive_to->cnt.d = dval;
        pthread_mutex_unlock(&dst->derive_to->mutex);
        dst->last_ts = dtime;
    }
}
