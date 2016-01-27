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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtp_info.h"
#include "rtp.h"
#include "rtp_analyze.h"
#include "rtpp_math.h"
#include "rtpp_refcnt.h"
#include "rtpp_ringbuf.h"

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

static void
update_jitter_stats(struct rtpp_session_stat_jitter *jp,
  struct rtp_info *rinfo, double rtime, int hint)
{
    int64_t dval, rtime_ts_delta;
    uint64_t rtime_ts, wrcorr;

    rtime_ts = rtp_dtime2time_ts64(rinfo->rtp_profile->ts_rate, rtime);
    if (rinfo->rtp_profile->pt_kind == RTP_PTK_AUDIO &&
      CALL_METHOD(jp->ts_dedup, locate, &rinfo->ts) >= 0) {
        jp->ts_dcount++;
        if (jp->pcount == 1) {
            jp->prev_rtime_ts = rtime_ts;
            jp->prev_ts = rinfo->ts;
        }
        return;
    }
    if (jp->prev_rtime_ts != 0) {
        if (hint == RTP_SEQ_RESET) {
            jp->seq_rcount++;
            goto saveandexit;
        }
        rtime_ts_delta = jp->prev_rtime_ts - rtime_ts;
        if (jp->prev_ts > rinfo->ts) {
            if ((jp->prev_ts - rinfo->ts) > (1 << 31)) {
                /* Normal case, timestamp wrap */
                wrcorr = (uint64_t)1 << 32;
#if 0
            } else if (rtime_ts_delta != 0 && (jp->prev_ts - rinfo->ts) >
              ABS(rtime_ts_delta) * 20) {
                /* Timestamp reset */
                jp->ts_rcount++;
                goto saveandexit;
#endif
            } else {
                wrcorr = 0;
            }
        } else {
# if 0
            if (rtime_ts_delta != 0 && (rinfo->ts - jp->prev_ts) >
              ABS(rtime_ts_delta) * 1024) {
                /* Timestamp jump */
                jp->ts_jcount++;
                goto saveandexit;
            }
#endif
            wrcorr = 0;
        }
        dval = (rtime_ts - ((uint64_t)rinfo->ts + wrcorr)) -
          (jp->prev_rtime_ts - jp->prev_ts);
        jp->jval = jp->jval + (double)(ABS(dval) - jp->jval) / 16.0;
        if (jp->jval > jp->jmax) {
            jp->jmax = jp->jval;
        }
        jp->jtotal += jp->jval;
    }
#if RTPP_DEBUG_analyze
    fprintf(stderr, SSRC_FMT ",%lld,%llu,%u,%f\n", rinfo->ssrc, jp->pcount,
      rtime_ts, rinfo->ts, jp->jval);
#endif
    jp->pcount++;
saveandexit:
    if (rinfo->rtp_profile->pt_kind == RTP_PTK_AUDIO) {
        CALL_METHOD(jp->ts_dedup, push, &rinfo->ts);
    }
    jp->prev_rtime_ts = rtime_ts;
    jp->prev_ts = rinfo->ts;
}

int
rtpp_stats_init(struct rtpp_session_stat *stat)
{
    struct rtpp_session_stat_jitter *jp;

    memset(stat, '\0', sizeof(struct rtpp_session_stat));
    jp = &stat->jitter;
    jp->ts_dedup = rtpp_ringbuf_ctor(sizeof(jp->prev_ts), 10);
    if (jp->ts_dedup == NULL) {
        return (-1);
    }
    return (0);
}

void
rtpp_stats_destroy(struct rtpp_session_stat *stat)
{
    struct rtpp_session_stat_jitter *jp;

    jp = &stat->jitter;
    CALL_METHOD(jp->ts_dedup->rcnt, decref);
}

enum update_rtpp_stats_rval
update_rtpp_stats(struct rtpp_log *rlog, struct rtpp_session_stat *stat, rtp_hdr_t *header,
  struct rtp_info *rinfo, double rtime)
{
    uint32_t seq;
    uint16_t idx;
    uint32_t mask;
    const struct rtp_profile *rpp;

    rpp = rinfo->rtp_profile;
    if (stat->ssrc_changes == 0) {
        RTPP_DBG_ASSERT(stat->last.pcount == 0);
        RTPP_DBG_ASSERT(stat->psent == 0);
        RTPP_DBG_ASSERT(stat->precvd == 0);
        stat->last.ssrc = rinfo->ssrc;
        stat->last.max_seq = stat->last.min_seq = rinfo->seq;
        stat->last.base_ts = rinfo->ts;
        stat->last.base_rtime = rtime;
        stat->last.pcount = 1;
        stat->ssrc_changes = 1;
        idx = (rinfo->seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        if (rpp->ts_rate > 0) {
            update_jitter_stats(&stat->jitter, rinfo, rtime, RTP_NORMAL);
        }
        return (UPDATE_OK);
    }
    if (stat->last.ssrc != rinfo->ssrc) {
        update_rtpp_totals(stat, stat);
        stat->last.duplicates = 0;
        memset(stat->last.seen, '\0', sizeof(stat->last.seen));
        LOGI_IF_NOT_NULL(rlog, "SSRC changed from " SSRC_FMT "/%d to "
          SSRC_FMT "/%d", stat->last.ssrc, stat->last.seq, rinfo->ssrc,
          rinfo->seq); 
        stat->last.ssrc = rinfo->ssrc;
        stat->last.max_seq = stat->last.min_seq = rinfo->seq;
        stat->last.base_ts = rinfo->ts;
        stat->last.base_rtime = rtime;
        stat->last.pcount = 1;
        stat->ssrc_changes += 1;
        if ((stat->psent > 0 || stat->precvd > 0) && rlog != NULL) {
            LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: ssrc_changes=%u, psent=%u, precvd=%u\n",
              rinfo->ssrc, rinfo->seq, stat->ssrc_changes, stat->psent, stat->precvd);
        }
        idx = (rinfo->seq % 131072) >> 5;
        stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
        stat->last.seq = rinfo->seq;
        if (rpp->ts_rate > 0) {
            update_jitter_stats(&stat->jitter, rinfo, rtime, RTP_SSRC_RESET);
        }
        return (UPDATE_SSRC_CHG);
    }
    seq = rinfo->seq + stat->last.seq_offset;
    if (header->mbt && (seq < stat->last.max_seq && (stat->last.max_seq & 0xffff) != 65535)) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: seq reset last->max_seq=%u, seq=%u, m=%u\n",
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
        if (rpp->ts_rate > 0) {
            update_jitter_stats(&stat->jitter, rinfo, rtime, RTP_SEQ_RESET);
        }
        return (UPDATE_OK);
    } else {
        if (rpp->ts_rate > 0) {
            if (seq == 0 && (stat->last.max_seq & 0xffff) < 65500) {
                update_jitter_stats(&stat->jitter, rinfo, rtime, RTP_SEQ_RESET);
            } else {
                update_jitter_stats(&stat->jitter, rinfo, rtime, RTP_NORMAL);
            }
        }
    }
    if (rpp->ts_rate != 0 && ABS(rtime - stat->last.base_rtime -
      rtp_ts2dtime(rpp->ts_rate, rinfo->ts - stat->last.base_ts)) > 0.1) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: delta rtime=%f, delta ts=%f\n",
          rinfo->ssrc, rinfo->seq, rtime - stat->last.base_rtime,
          rtp_ts2dtime(rpp->ts_rate, rinfo->ts - stat->last.base_ts));
        stat->last.base_rtime = rtime;
    }
    if (stat->last.max_seq % 65536 < 536 && rinfo->seq > 65000) {
        /* Pre-wrap packet received after a wrap */
        seq -= 65536;
    } else if (stat->last.max_seq > 65000 && seq < stat->last.max_seq - 65000) {
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: wrap last->max_seq=%u, seq=%u\n",
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
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: desync last->max_seq=%u, seq=%u, m=%u\n",
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
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: DUP\n",
          rinfo->ssrc, rinfo->seq);
        stat->last.duplicates += 1;
        stat->last.seq = rinfo->seq;
        return (UPDATE_OK);
    }
    stat->last.seen[idx] |= 1 << (rinfo->seq & 31);
    if (seq - stat->last.max_seq != 1)
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: delta = %d\n",
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
        LOGD_IF_NOT_NULL(rlog, SSRC_FMT "/%d: last->min_seq=%u\n",
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
