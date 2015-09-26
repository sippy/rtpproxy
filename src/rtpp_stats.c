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
#include <pthread.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_pearson.h"
#include "rtpp_stats.h"
#include "rtpp_util.h"

struct rtpp_stat
{
    const char *name;
    pthread_mutex_t mutex;
    union {
      uint64_t u64;
      double d;
    } cnt;
};

struct rtpp_stat_derived
{
    struct rtpp_stat stat;
    double last_ts;
    struct rtpp_stat last_val;
};

enum rtpp_cnt_type {
    RTPP_CNT_U64,
    RTPP_CNT_DBL
};

struct rtpp_stats_derived
{
    const char *name;
    const char *descr;
};    

static struct rtpp_stats_derived rtpp_stats_pps_in = {
    .name = "pps_in",                .descr = "Rate at which RTP/RTPC packets are received (packets per second)"
};

static struct rtpp_stats
{
    const char *name;
    const char *descr;
    enum rtpp_cnt_type type;
    struct rtpp_stats_derived *derive;
} default_stats[] = {
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
    {.name = "npkts_rcvd",           .descr = "Total number of RTP/RTPC packets received", .type = RTPP_CNT_U64, .derive = &rtpp_stats_pps_in},
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
    {.name = NULL}
};

struct rtpp_stats_obj_priv
{
    int nstats;
    struct rtpp_stat *stats;
    struct rtpp_pearson_perfect *rppp;
};

struct rtpp_stats_obj_full
{
    struct rtpp_stats_obj pub;
    struct rtpp_stats_obj_priv pvt;
};

static void rtpp_stats_obj_dtor(struct rtpp_stats_obj *);
static int rtpp_stats_obj_getidxbyname(struct rtpp_stats_obj *, const char *);
static int rtpp_stats_obj_updatebyidx(struct rtpp_stats_obj *, int, uint64_t);
static int rtpp_stats_obj_updatebyname(struct rtpp_stats_obj *, const char *, uint64_t);
static int rtpp_stats_obj_updatebyname_d(struct rtpp_stats_obj *, const char *, double);
static int64_t rtpp_stats_obj_getlvalbyname(struct rtpp_stats_obj *, const char *);
static int rtpp_stats_obj_nstr(struct rtpp_stats_obj *, char *, int, const char *);
static int rtpp_stats_obj_getnstats(struct rtpp_stats_obj *);

static const char *
getdstat(void *p, int n)
{
    struct rtpp_stats_obj_priv *pvt;

    pvt = (struct rtpp_stats_obj_priv *)p;
    if (n >= pvt->nstats) {
        return (NULL);
    }

    return (pvt->stats[n].name);
}

static int
count_rtpp_stats(struct rtpp_stats *sp)
{
    int nstats, i;

    nstats = 0;
    for (i = 0; sp[i].name != NULL; i++) {
        nstats += 1;
        if (sp[i].derive != NULL) {
            nstats += 1;
        }
    }
    return (nstats);
}

struct rtpp_stats_obj *
rtpp_stats_ctor(void)
{
    struct rtpp_stats_obj_full *fp;
    struct rtpp_stats_obj *pub;
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;
    int i;

    fp = rtpp_zmalloc(sizeof(struct rtpp_stats_obj_full));
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
    for (i = 0; default_stats[i].name != NULL; i++) {
        st = &pvt->stats[i];
        st->name = default_stats[i].name;
        if (pthread_mutex_init(&st->mutex, NULL) != 0) {
            while ((i - 1) >= 0) {
                st = &pvt->stats[i - 1];
                pthread_mutex_destroy(&st->mutex);
                i -= 1;
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
    pub->dtor = &rtpp_stats_obj_dtor;
    pub->getidxbyname = &rtpp_stats_obj_getidxbyname;
    pub->updatebyidx = &rtpp_stats_obj_updatebyidx;
    pub->updatebyname = &rtpp_stats_obj_updatebyname;
    pub->updatebyname_d = &rtpp_stats_obj_updatebyname_d;
    pub->getlvalbyname = &rtpp_stats_obj_getlvalbyname;
    pub->nstr = &rtpp_stats_obj_nstr;
    pub->getnstats = &rtpp_stats_obj_getnstats;
    return (pub);
e2:
    free(pvt->stats);
e1:
    free(fp);
e0:
    return (NULL);
}

static int
rtpp_stats_obj_getidxbyname(struct rtpp_stats_obj *self, const char *name)
{
    struct rtpp_stats_obj_priv *pvt;

    pvt = self->pvt;
    return (rtpp_pearson_perfect_hash(pvt->rppp, name));
}

static int
rtpp_stats_obj_updatebyidx_internal(struct rtpp_stats_obj *self, int idx,
  enum rtpp_cnt_type type, void *argp)
{
    struct rtpp_stats_obj_priv *pvt;
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
rtpp_stats_obj_updatebyidx(struct rtpp_stats_obj *self, int idx, uint64_t incr)
{

    return rtpp_stats_obj_updatebyidx_internal(self, idx, RTPP_CNT_U64, &incr);
}

static int
rtpp_stats_obj_updatebyname(struct rtpp_stats_obj *self, const char *name, uint64_t incr)
{
    int idx;

    idx = rtpp_stats_obj_getidxbyname(self, name);
    return rtpp_stats_obj_updatebyidx_internal(self, idx, RTPP_CNT_U64, &incr);
}

static int
rtpp_stats_obj_updatebyname_d(struct rtpp_stats_obj *self, const char *name, double incr)
{
    int idx;

    idx = rtpp_stats_obj_getidxbyname(self, name);
    return rtpp_stats_obj_updatebyidx_internal(self, idx, RTPP_CNT_DBL, &incr);
}

static int64_t
rtpp_stats_obj_getlvalbyname(struct rtpp_stats_obj *self, const char *name)
{
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;
    uint64_t rval;
    int idx;

    idx = rtpp_stats_obj_getidxbyname(self, name);
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
rtpp_stats_obj_nstr(struct rtpp_stats_obj *self, char *buf, int len, const char *name)
{
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;
    int idx, rval;
    uint64_t uval;
    double dval;

    idx = rtpp_stats_obj_getidxbyname(self, name);
    if (idx < 0) {
        return (-1);
    }
    pvt = self->pvt;
    st = &pvt->stats[idx];
    if (default_stats[idx].type == RTPP_CNT_U64) {
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
rtpp_stats_obj_dtor(struct rtpp_stats_obj *self)
{
    int i;
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;

    pvt = self->pvt;
    for (i = 0; i < pvt->nstats; i++) {
        st = &pvt->stats[i];
        pthread_mutex_destroy(&st->mutex);
    }
    rtpp_pearson_perfect_dtor(pvt->rppp);
    free(pvt->stats);
    free(self);
}

static int
rtpp_stats_obj_getnstats(struct rtpp_stats_obj *self)
{

    return (self->pvt->nstats);
}
