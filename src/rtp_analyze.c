/*
 * Copyright (c) 2009 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtp_info.h"
#include "rtp.h"
#include "rtp_analyze.h"
#include "rtpp_math.h"
#include "rtpp_refcnt.h"
#include "rtpp_ringbuf.h"

struct rtp_analyze_jdata;

struct rtp_analyze_jitter {
    int jdlen;
    double jmax_acum;
    double jtotal_acum;
    long long jvcount_acum;
    long long pcount_acum;
    struct rtp_analyze_jdata *first;
};

struct rtp_analyze_jdata_ssrc {
    uint64_t prev_rtime_ts;
    uint32_t prev_ts;
#if 0
    long long ts_rcount;
    long long ts_jcount;
#endif
    long long ts_dcount;
    long long seq_rcount;
    double jlast;
    double jmax;
    double jtotal;
    long long pcount;
};

struct rtp_analyze_jdata {
    struct rtp_analyze_jdata_ssrc jss;
    struct rtpp_ringbuf *ts_dedup;
    struct rtpp_ssrc ssrc;
    struct rtp_analyze_jdata *next;
};

static double
rtp_ts2dtime(int ts_rate, uint32_t ts)
{

    return ((double)ts) / ((double)ts_rate);
}

static uint64_t
rtp_dtime2time_ts64(int ts_rate, double dtime)
{

    return (uint64_t)(dtime * (double)ts_rate);
}

/* rlog can be null in this context, when compiled for the extractaudio context */
#define LOGD_IF_NOT_NULL(log, args...) \
    if ((log) != NULL) { \
        RTPP_LOG((log), RTPP_LOG_DBUG, ## args); \
    }
#define LOGI_IF_NOT_NULL(log, args...) \
    if ((log) != NULL) { \
        RTPP_LOG((log), RTPP_LOG_INFO, ## args); \
    }

#define RTP_NORMAL     0
#define RTP_SEQ_RESET  1
#define RTP_SSRC_RESET 2

#define RTPC_JDATA_MAX 10

static void
update_jitter_stats(struct rtp_analyze_jdata *jdp,
  struct rtp_info *rinfo, double rtime, int hint)
{
    int64_t dval;
    uint64_t rtime_ts, wrcorr;
#if 0
    int64_t rtime_ts_delta;
#endif

    rtime_ts = rtp_dtime2time_ts64(rinfo->rtp_profile->ts_rate, rtime);
    if (rinfo->rtp_profile->pt_kind == RTP_PTK_AUDIO &&
      CALL_METHOD(jdp->ts_dedup, locate, &rinfo->ts) >= 0) {
        jdp->jss.ts_dcount++;
        if (jdp->jss.pcount == 1) {
            jdp->jss.prev_rtime_ts = rtime_ts;
            jdp->jss.prev_ts = rinfo->ts;
        }
        return;
    }
    if (jdp->jss.prev_rtime_ts != 0) {
        if (hint == RTP_SEQ_RESET) {
            jdp->jss.seq_rcount++;
            goto saveandexit;
        }
#if 0
        rtime_ts_delta = jdp->jss.prev_rtime_ts - rtime_ts;
#endif
        if (jdp->jss.prev_ts > rinfo->ts) {
            if ((jdp->jss.prev_ts - rinfo->ts) > (1 << 31)) {
                /* Normal case, timestamp wrap */
                wrcorr = (uint64_t)1 << 32;
#if 0
            } else if (rtime_ts_delta != 0 && (jdp->jss.prev_ts - rinfo->ts) >
              ABS(rtime_ts_delta) * 20) {
                /* Timestamp reset */
                jdp->jss.ts_rcount++;
                goto saveandexit;
#endif
            } else {
                wrcorr = 0;
            }
        } else {
# if 0
            if (rtime_ts_delta != 0 && (rinfo->ts - jdp->jss.prev_ts) >
              ABS(rtime_ts_delta) * 1024) {
                /* Timestamp jump */
                jdp->jss.ts_jcount++;
                goto saveandexit;
            }
#endif
            wrcorr = 0;
        }
        dval = (rtime_ts - ((uint64_t)rinfo->ts + wrcorr)) -
          (jdp->jss.prev_rtime_ts - jdp->jss.prev_ts);
        jdp->jss.jlast = jdp->jss.jlast + (double)(ABS(dval) - jdp->jss.jlast) / 16.0;
        if (jdp->jss.jlast > jdp->jss.jmax) {
            jdp->jss.jmax = jdp->jss.jlast;
        }
        jdp->jss.jtotal += jdp->jss.jlast;
    }
#if RTPP_DEBUG_analyze
    fprintf(stderr, SSRC_FMT ",%lld,%llu,%u,%f\n", rinfo->ssrc, jdp->jss.pcount,
      rtime_ts, rinfo->ts, jdp->jss.jlast);
#endif
    jdp->jss.pcount++;
saveandexit:
    if (rinfo->rtp_profile->pt_kind == RTP_PTK_AUDIO) {
        CALL_METHOD(jdp->ts_dedup, push, &rinfo->ts);
    }
    jdp->jss.prev_rtime_ts = rtime_ts;
    jdp->jss.prev_ts = rinfo->ts;
}

static struct rtp_analyze_jitter *rtp_analyze_jt_ctor(void);

int
rtpp_stats_init(struct rtpp_session_stat *stat)
{

    memset(stat, '\0', sizeof(struct rtpp_session_stat));
    stat->jdata = rtp_analyze_jt_ctor();
    if (stat->jdata == NULL) {
        return (-1);
    }
    stat->last.pt = PT_UNKN;
    return (0);
}

static struct rtp_analyze_jdata *
rtp_analyze_jdata_ctor()
{
    struct rtp_analyze_jdata *jdp;

    jdp = rtpp_zmalloc(sizeof(*jdp));
    if (jdp == NULL) {
        goto e0;
    }
    jdp->ts_dedup = rtpp_ringbuf_ctor(sizeof(jdp->jss.prev_ts), 10);
    if (jdp->ts_dedup == NULL) {
        goto e1;
    }
    return (jdp);

e1:
    free(jdp);
e0:
    return (NULL);
}

static struct rtp_analyze_jitter *
rtp_analyze_jt_ctor()
{
    struct rtp_analyze_jitter *jp;

    jp = rtpp_zmalloc(sizeof(*jp));
    if (jp == NULL) {
        goto e0;
    }
    jp->first = rtp_analyze_jdata_ctor();
    if (jp->first == NULL) {
        goto e1;
    }
    jp->jdlen = 1;
    return (jp);

e1:
    free(jp);
e0:
    return (NULL);
}


static void rtp_analyze_jt_destroy(struct rtp_analyze_jitter *);

void
rtpp_stats_destroy(struct rtpp_session_stat *stat)
{

    rtp_analyze_jt_destroy(stat->jdata);
}

static void
rtp_analyze_jt_destroy(struct rtp_analyze_jitter *jp)
{
    struct rtp_analyze_jdata *jdp, *jdp_next;

    for (jdp = jp->first; jdp != NULL; jdp = jdp_next) {
        jdp_next = jdp->next;
        CALL_SMETHOD(jdp->ts_dedup->rcnt, decref);
        free(jdp);
        jp->jdlen -= 1;
    }
    RTPP_DBG_ASSERT(jp->jdlen == 0);
    free(jp);
}

static struct rtp_analyze_jdata *
jdata_by_ssrc(struct rtp_analyze_jitter *jp, uint32_t ssrc)
{
    struct rtp_analyze_jdata *rjdp, *jdp_last, *jdp_prelast;

    if (jp->first->ssrc.inited == 0) {
        jp->first->ssrc.val = ssrc;
        jp->first->ssrc.inited = 1;
        return (jp->first);
    }

    jdp_last = jdp_prelast = NULL;
    for (rjdp = jp->first; rjdp != NULL; rjdp = rjdp->next) {
        if (rjdp->ssrc.val == ssrc) {
            return (rjdp);
        }
        jdp_prelast = jdp_last;
        jdp_last = rjdp;
    }

    if (jp->jdlen == RTPC_JDATA_MAX) {
        /* Re-use the last per-ssrc data */
        rjdp = jdp_last;
        if (jdp_prelast != NULL) {
            RTPP_DBG_ASSERT(jdp_prelast->next == jdp_last);
            jdp_prelast->next = NULL;
        } else {
            jp->first = NULL;
        }
        CALL_METHOD(rjdp->ts_dedup, flush);
        if (rjdp->jss.pcount >= 2) {
            if (jp->jmax_acum < rjdp->jss.jmax) {
                jp->jmax_acum = rjdp->jss.jmax;
            }
            jp->jtotal_acum += rjdp->jss.jtotal;
            jp->jvcount_acum += rjdp->jss.pcount - 1;
            jp->pcount_acum += rjdp->jss.pcount;
        }
        memset(&rjdp->jss, '\0', sizeof(rjdp->jss));
        RTPP_DBG_ASSERT(rjdp->ssrc.inited == 1);
    } else {
        /* Allocate per-ssrc data */
        rjdp = rtp_analyze_jdata_ctor();
        if (rjdp == NULL) {
            return (NULL);
        }
        rjdp->ssrc.inited = 1;
        jp->jdlen += 1;
    }
    rjdp->ssrc.val = ssrc;
    rjdp->next = jp->first;
    jp->first = rjdp;
    return (rjdp);
}

enum update_rtpp_stats_rval
update_rtpp_stats(struct rtpp_log *rlog, struct rtpp_session_stat *stat, rtp_hdr_t *header,
  struct rtp_info *rinfo, double rtime)
{
    uint32_t seq;
    uint16_t idx;
    uint32_t mask;
    const struct rtp_profile *rpp;
    struct rtp_analyze_jdata *jdp;

    rpp = rinfo->rtp_profile;
    jdp = jdata_by_ssrc(stat->jdata, rinfo->ssrc);
    if (stat->ssrc_changes == 0) {
        RTPP_DBG_ASSERT(stat->last.pcount == 0);
        RTPP_DBG_ASSERT(stat->psent == 0);
        RTPP_DBG_ASSERT(stat->precvd == 0);
        stat->last.ssrc.val = rinfo->ssrc;
        stat->last.ssrc.inited = 1;
        stat->last.max_seq = stat->last.min_seq = rinfo->seq;
        stat->last.base_ts = rinfo->ts;
        stat->last.base_rtime = rtime;
        stat->last.pcount = 1;
        stat->ssrc_changes = 1;
        idx = (rinfo->seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        if (rpp->ts_rate > 0 && jdp != NULL) {
            update_jitter_stats(jdp, rinfo, rtime, RTP_NORMAL);
        }
        return (UPDATE_OK);
    }
    RTPP_DBG_ASSERT(stat->last.ssrc.inited == 1);
    if (stat->last.ssrc.val != rinfo->ssrc) {
        update_rtpp_totals(stat, stat);
        stat->last.duplicates = 0;
        memset(stat->last.seen, '\0', sizeof(stat->last.seen));
        LOGI_IF_NOT_NULL(rlog, "SSRC changed from " SSRC_FMT "/%d to "
          SSRC_FMT "/%d", stat->last.ssrc.val, stat->last.seq, rinfo->ssrc,
          rinfo->seq); 
        stat->last.ssrc.val = rinfo->ssrc;
        stat->last.max_seq = stat->last.min_seq = rinfo->seq;
        stat->last.base_ts = rinfo->ts;
        stat->last.base_rtime = rtime;
        stat->last.pcount = 1;
        stat->ssrc_changes += 1;
        if ((stat->psent > 0 || stat->precvd > 0) && rlog != NULL) {
            LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: ssrc_changes=%u, psent=%u, precvd=%u",
              rinfo->ssrc, rinfo->seq, stat->ssrc_changes, stat->psent, stat->precvd);
        }
        idx = (rinfo->seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        if (rpp->ts_rate > 0 && jdp != NULL) {
            update_jitter_stats(jdp, rinfo, rtime, RTP_SSRC_RESET);
        }
        return (UPDATE_SSRC_CHG);
    }
    seq = rinfo->seq + stat->last.seq_offset;
    if (header->mbt && (seq < stat->last.max_seq && (stat->last.max_seq & 0xffff) != 65535)) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: seq reset last->max_seq=%u, seq=%u, m=%u",
          rinfo->ssrc, rinfo->seq, stat->last.max_seq, seq, header->mbt);
        /* Seq reset has happened. Treat it as a ssrc change */
        update_rtpp_totals(stat, stat);
        stat->last.duplicates = 0;
        memset(stat->last.seen, '\0', sizeof(stat->last.seen));
        stat->last.max_seq = stat->last.min_seq = seq;
        stat->last.base_ts = rinfo->ts;
        stat->last.base_rtime = rtime;
        stat->last.pcount = 1;
        stat->seq_res_count += 1;
        idx = (seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        if (rpp->ts_rate > 0 && jdp != NULL) {
            update_jitter_stats(jdp, rinfo, rtime, RTP_SEQ_RESET);
        }
        return (UPDATE_OK);
    } else {
        if (rpp->ts_rate > 0 && jdp != NULL) {
            if (seq == 0 && (stat->last.max_seq & 0xffff) < 65500) {
                update_jitter_stats(jdp, rinfo, rtime, RTP_SEQ_RESET);
            } else {
                update_jitter_stats(jdp, rinfo, rtime, RTP_NORMAL);
            }
        }
    }
    if (rpp->ts_rate != 0 && ABS(rtime - stat->last.base_rtime -
      rtp_ts2dtime(rpp->ts_rate, rinfo->ts - stat->last.base_ts)) > 0.1) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: delta rtime=%f, delta ts=%f",
          rinfo->ssrc, rinfo->seq, rtime - stat->last.base_rtime,
          rtp_ts2dtime(rpp->ts_rate, rinfo->ts - stat->last.base_ts));
        stat->last.base_rtime = rtime;
    }
    if (stat->last.max_seq % 65536 < 536 && rinfo->seq > 65000) {
        /* Pre-wrap packet received after a wrap */
        seq -= 65536;
    } else if (stat->last.max_seq > 65000 && seq < stat->last.max_seq - 65000) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: wrap last->max_seq=%u, seq=%u",
          rinfo->ssrc, rinfo->seq, stat->last.max_seq, seq);
        /* Wrap up has happened */
        stat->last.seq_offset += 65536;
        seq += 65536;
        if (stat->last.seq_offset % 131072 == 65536) {
            memset(stat->last.seen + 2048, '\0', sizeof(stat->last.seen) / 2);
        } else {
            memset(stat->last.seen, '\0', sizeof(stat->last.seen) / 2);
        }
    } else if (seq + 536 < stat->last.max_seq || seq > stat->last.max_seq + 536) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: desync last->max_seq=%u, seq=%u, m=%u",
          rinfo->ssrc, rinfo->seq, stat->last.max_seq, seq, header->mbt);
        /* Desynchronization has happened. Treat it as a ssrc change */
        update_rtpp_totals(stat, stat);
        stat->last.duplicates = 0;
        memset(stat->last.seen, '\0', sizeof(stat->last.seen));
        stat->last.max_seq = stat->last.min_seq = seq;
        stat->last.pcount = 1;
        stat->desync_count += 1;
        idx = (seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
        /* printf("last->max_seq=%u, seq=%u, m=%u\n", stat->last.max_seq, seq, header->mbt);*/
    idx = (seq % 131072) >> 5;
    mask = stat->last.seen[idx];
    if (((mask >> (seq & 31)) & 1) != 0) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: DUP",
          rinfo->ssrc, rinfo->seq);
        stat->last.duplicates += 1;
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
    stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
    if (seq - stat->last.max_seq != 1)
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: delta = %d",
          rinfo->ssrc, rinfo->seq, seq - stat->last.max_seq);
    if (seq >= stat->last.max_seq) {
        stat->last.max_seq = seq;
        stat->last.pcount += 1;
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
    if (seq >= stat->last.min_seq) {
        stat->last.pcount += 1;
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
    if (stat->last.seq_offset == 0 && seq < stat->last.min_seq) {
        stat->last.min_seq = seq;
        stat->last.pcount += 1;
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: last->min_seq=%u",
          rinfo->ssrc, rinfo->seq, stat->last.min_seq);
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
    /* XXX something wrong with the stream */
    stat->last.seq = rinfo->seq;
    return (UPDATE_ERR);
}

void
update_rtpp_totals(struct rtpp_session_stat *wstat, struct rtpp_session_stat *ostat)
{

    if (ostat != wstat) {
        ostat->psent = wstat->psent;
        ostat->precvd = wstat->precvd;
        ostat->duplicates = wstat->duplicates;
    }
    if (wstat->last.pcount == 0)
        return;
    ostat->psent += wstat->last.max_seq - wstat->last.min_seq + 1;
    ostat->precvd += wstat->last.pcount;
    ostat->duplicates += wstat->last.duplicates;
}

int
get_jitter_stats(struct rtp_analyze_jitter *jp, struct rtpa_stats_jitter *jst)
{
    int i;
    struct rtp_analyze_jdata *rjdp;
    double jtotal;

    i = 0;
    for (rjdp = jp->first; rjdp != NULL && rjdp->ssrc.inited == 1; rjdp = rjdp->next) {
        if (rjdp->jss.pcount < 2) {
            continue;
        }
        if (i == 0) {
            jst->jlast = rjdp->jss.jlast;
            jst->jmax = MAX(jp->jmax_acum, rjdp->jss.jmax);
            jtotal = jp->jtotal_acum + rjdp->jss.jtotal;
            jst->jvcount = jp->jvcount_acum + rjdp->jss.pcount - 1;
            jst->pcount = jp->pcount_acum + rjdp->jss.pcount;
        } else {
            if (jst->jmax < rjdp->jss.jmax) {
                jst->jmax = rjdp->jss.jmax;
            }
            jtotal += rjdp->jss.jtotal;
            jst->jvcount += rjdp->jss.pcount - 1;
            jst->pcount += rjdp->jss.pcount;
        }
        i += 1;
    }
    if (i > 0) {
        jst->javg = jtotal / (double)(jst->jvcount);
    }
    return (i);
}
