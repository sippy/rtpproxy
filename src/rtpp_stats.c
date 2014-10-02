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
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_stats.h"

struct rtpp_stat
{
    const char *name;
    pthread_mutex_t mutex;
    uint64_t cnt;
};

#define RTPP_NSTATS 18

static struct
{
    const char *name;
    const char *descr;
} default_stats[RTPP_NSTATS] = {
    {.name = "nsess_created",   .descr = "Number of RTP sessions created"},
    {.name = "nsess_destroyed", .descr = "Number of RTP sessions destroyed"},
    {.name = "nsess_nortp",     .descr = "Number of sessions that had no RTP neither in nor out"},
    {.name = "nsess_owrtp",     .descr = "Number of sessions that had one-way RTP only"},
    {.name = "nsess_nortcp",    .descr = "Number of sessions that had no RTCP neither in nor out"},
    {.name = "nsess_owrtcp",    .descr = "Number of sessions that had one-way RTCP only"}, 
    {.name = "nplrs_created",   .descr = "Number of RTP players created"},
    {.name = "nplrs_destroyed", .descr = "Number of RTP players destroyed"},
    {.name = "npkts_rcvd",      .descr = "Total number of RTP/RTPC packets received"},
    {.name = "npkts_played",    .descr = "Total number of RTP packets locally generated (played out)"},
    {.name = "npkts_relayed",   .descr = "Total number of RTP/RTPC packets relayed"},
    {.name = "npkts_resized",   .descr = "Total number of RTP packets resized (re-packetized)"},
    {.name = "npkts_discard",   .descr = "Total number of RTP/RTPC packets discarded"},
    {.name = "total_duration",  .descr = "Cumulative duration of all sessions"},
    {.name = "ncmds_rcvd",      .descr = "Total number of control commands received"},
    {.name = "ncmds_succd",     .descr = "Total number of control commands successfully processed"},
    {.name = "ncmds_errs",      .descr = "Total number of control commands ended up with an error"},
    {.name = "ncmds_repld",     .descr = "Total number of control commands that had a reply generated"}
};

struct rtpp_stats_obj_priv
{
    struct rtpp_stat *stats;
};

struct rtpp_stats_obj_full
{
    struct rtpp_stats_obj pub;
    struct rtpp_stats_obj_priv pvt;
};

static void rtpp_stats_obj_dtor(struct rtpp_stats_obj *);
static int rtpp_stats_obj_getidxbyname(struct rtpp_stats_obj *, const char *);
static int rtpp_stats_obj_updatebyidx(struct rtpp_stats_obj *, int, uint64_t);
static int64_t rtpp_stats_obj_getlvalbyname(struct rtpp_stats_obj *, const char *);

struct rtpp_stats_obj *
rtpp_stats_ctor(void)
{
    struct rtpp_stats_obj_full *fp;
    struct rtpp_stats_obj *pub;
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;
    int i;

    fp = malloc(sizeof(struct rtpp_stats_obj_full));
    if (fp == NULL) {
        return (NULL);
    }
    memset(fp, '\0', sizeof(struct rtpp_stats_obj_full));
    pub = &(fp->pub);
    pvt = &(fp->pvt);
    pvt->stats = malloc(sizeof(struct rtpp_stat) * RTPP_NSTATS);
    if (pvt->stats == NULL) {
        free(fp);
        return (NULL);
    }
    memset(pvt->stats, '\0', sizeof(struct rtpp_stat) * RTPP_NSTATS);
    for (i = 0; i < RTPP_NSTATS; i++) {
        st = &pvt->stats[i];
        st->name = default_stats[i].name;
        if (pthread_mutex_init(&st->mutex, NULL) != 0) {
            free(pvt->stats);
            free(fp);
            return (NULL);
        }
        st->cnt = 0;
    }
    pub->pvt = pvt;
    pub->dtor = &rtpp_stats_obj_dtor;
    pub->getidxbyname = &rtpp_stats_obj_getidxbyname;
    pub->updatebyidx = &rtpp_stats_obj_updatebyidx;
    pub->getlvalbyname = &rtpp_stats_obj_getlvalbyname;
    return (pub);
}

static int
rtpp_stats_obj_getidxbyname(struct rtpp_stats_obj *self, const char *name)
{
    int i;
    struct rtpp_stats_obj_priv *pvt;

    pvt = self->pvt;
    for (i = 0; i < RTPP_NSTATS; i++) {
        if (strcmp(pvt->stats[i].name, name) != 0)
            continue;
        return (i);
    }
    return (-1);
}

static int
rtpp_stats_obj_updatebyidx(struct rtpp_stats_obj *self, int idx, uint64_t incr)
{
    int i;
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;

    if (idx < 0 || idx >= RTPP_NSTATS)
        return (-1);
    pvt = self->pvt;
    st = &pvt->stats[i];
    pthread_mutex_lock(&st->mutex);
    st->cnt += incr;
    pthread_mutex_unlock(&st->mutex);
    return (0);
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
    rval = st->cnt;
    pthread_mutex_unlock(&st->mutex);
    return (rval);
}

static void
rtpp_stats_obj_dtor(struct rtpp_stats_obj *self)
{
    int i;
    struct rtpp_stats_obj_priv *pvt;
    struct rtpp_stat *st;

    pvt = self->pvt;
    for (i = 0; i < RTPP_NSTATS; i++) {
        st = &pvt->stats[i];
        pthread_mutex_destroy(&st->mutex);
    }
    free(pvt->stats);
    free(self);
}
