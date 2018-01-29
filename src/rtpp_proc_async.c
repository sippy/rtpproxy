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
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <elperiodic.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_weakref.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_async.h"
#include "rtpp_debug.h"
#if RTPP_DEBUG_timers
#include "rtpp_math.h"
#endif
#include "rtpp_netio_async.h"
#include "rtpp_proc.h"
#include "rtpp_proc_async.h"
#include "rtpp_proc_servers.h"
#include "rtpp_proc_ttl.h"
#include "rtpp_mallocs.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_pipe.h"

struct rtpp_proc_async_cf {
    struct rtpp_proc_async pub;
    pthread_t thread_id;
    long long clock_tick;
    long long ncycles_ref;
    struct rtpp_anetio_cf *op;
#if RTPP_DEBUG_timers
    struct recfilter sleep_time;
    struct recfilter poll_time;
    struct recfilter proc_time;
#endif
    struct rtpp_proc_rstats rstats;
    struct cfg *cf_save;
    int tstate;
    pthread_mutex_t tstate_lock;
    void *elp;
};

#define TSTATE_RUN   0x0
#define TSTATE_CEASE 0x1

static void rtpp_proc_async_dtor(struct rtpp_proc_async *);

#define PUB2PVT(pubp)      ((struct rtpp_proc_async_cf *)((char *)(pubp) - offsetof(struct rtpp_proc_async_cf, pub)))

#define FLUSH_STAT(sobj, st)	{ \
    if ((st).cnt > 0) { \
        CALL_SMETHOD(sobj, updatebyidx, (st).cnt_idx, (st).cnt); \
        (st).cnt = 0; \
    } \
}

static void
flush_rstats(struct rtpp_stats *sobj, struct rtpp_proc_rstats *rsp)
{

    FLUSH_STAT(sobj, rsp->npkts_rcvd);
    FLUSH_STAT(sobj, rsp->npkts_played);
    FLUSH_STAT(sobj, rsp->npkts_relayed);
    FLUSH_STAT(sobj, rsp->npkts_resizer_in);
    FLUSH_STAT(sobj, rsp->npkts_resizer_out);
    FLUSH_STAT(sobj, rsp->npkts_resizer_discard);
    FLUSH_STAT(sobj, rsp->npkts_discard);
}

static void
init_rstats(struct rtpp_stats *sobj, struct rtpp_proc_rstats *rsp)
{

    rsp->npkts_rcvd.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_rcvd");
    rsp->npkts_played.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_played");
    rsp->npkts_relayed.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_relayed");
    rsp->npkts_resizer_in.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_in");
    rsp->npkts_resizer_out.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_out");
    rsp->npkts_resizer_discard.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_discard");
    rsp->npkts_discard.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_discard");
}

static void
rtpp_proc_async_run(void *arg)
{
    struct cfg *cf;
    double last_tick_time, lv;
    int alarm_tick, ndrain, rtp_only;
    int nready_rtp, nready_rtcp;
    struct rtpp_proc_async_cf *proc_cf;
    long long ncycles_ref, ncycles_ref_last;
#if RTPP_DEBUG_timers
    int ncycles_ref_pre;
#endif
#if RTPP_DEBUG_timers || RTPP_DEBUG_netio
    long long last_ctick;
#endif
    struct sthread_args *sender;
    double tp[4];
    struct rtpp_proc_rstats *rstats;
    struct rtpp_stats *stats_cf;
    struct rtpp_polltbl ptbl_rtp;
    struct rtpp_polltbl ptbl_rtcp;
    int tstate, overload;

    proc_cf = (struct rtpp_proc_async_cf *)arg;
    cf = proc_cf->cf_save;
    stats_cf = cf->stable->rtpp_stats;
    rstats = &proc_cf->rstats;

    memset(&ptbl_rtp, '\0', sizeof(struct rtpp_polltbl));
    memset(&ptbl_rtcp, '\0', sizeof(struct rtpp_polltbl));

    last_tick_time = 0;
#if RTPP_DEBUG_timers || RTPP_DEBUG_netio
    last_ctick = 0;
#endif
    ncycles_ref_last = 0;
    overload = 0;

    tp[0] = getdtime();
    for (;;) {
        ncycles_ref = (long long)prdic_getncycles_ref(proc_cf->elp);
        if (ncycles_ref % 10 == 0) {
            pthread_mutex_lock(&proc_cf->tstate_lock);
            tstate = proc_cf->tstate;
            pthread_mutex_unlock(&proc_cf->tstate_lock);
            if (tstate == TSTATE_CEASE) {
                break;
            }
        }
        if (cf->stable->overload_prot.ecode != 0 && ncycles_ref % 20 == 0) {
            lv = prdic_getload(proc_cf->elp);
            if (overload  && lv < 0.85) {
                overload = 0;
                CALL_METHOD(cf->stable->rtpp_cmd_cf, reg_overload, 0);
            } else if (overload == 0 && lv > 0.9) {
                overload = 1;
                CALL_METHOD(cf->stable->rtpp_cmd_cf, reg_overload, 1);
            }
            if (ncycles_ref % 200 == 0) {
                RTPP_LOG(cf->stable->glog, RTPP_LOG_INFO, "ncycles=%lld load=%f",
                  ncycles_ref, lv);
            }
        }
        ndrain = (ncycles_ref - ncycles_ref_last) / (cf->stable->target_pfreq / MAX_RTP_RATE);
#if RTPP_DEBUG_timers
        ncycles_ref_pre = ncycles_ref_last;
#endif
        ncycles_ref_last = ncycles_ref;

        tp[1] = getdtime();
#if RTPP_DEBUG_timers
        if (last_ctick % (unsigned int)cf->stable->target_pfreq == 0 || last_ctick < 1000) {
            RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld sptime %f, CSV: %f,%f,%f", \
              last_ctick, tp[1], (double)last_ctick / cf->stable->target_pfreq, \
              ((double)ncycles_ref_last / cf->stable->target_pfreq) - tp[1], tp[1]);
        }
#endif

        if (ndrain < 1) {
            ndrain = 1;
        }

#if RTPP_DEBUG_timers
        if (ndrain > 1) {
            RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld " \
              "ncycles_ref %lld, ncycles_ref_pre %lld, ndrain %d CSV: %f,%f,%d", \
              last_ctick, ncycles_ref_last, ncycles_ref_pre, ndrain, \
              (double)last_ctick / cf->stable->target_pfreq, ndrain);
        }
#endif

        alarm_tick = 0;
        if (last_tick_time == 0 || last_tick_time > tp[1]) {
            last_tick_time = tp[1];
        } else if (last_tick_time + (double)TIMETICK < tp[1]) {
            alarm_tick = 1;
            last_tick_time = tp[1];
        }

        if (alarm_tick || (ncycles_ref_last % 7) == 0) {
            rtp_only = 0;
        } else {
            rtp_only = 1;
        }

        CALL_METHOD(cf->stable->sessinfo, sync_polltbl, &ptbl_rtp, PIPE_RTP);
        nready_rtp = nready_rtcp = 0;
        if (ptbl_rtp.curlen > 0) {
            if (rtp_only == 0) {
                CALL_METHOD(cf->stable->sessinfo, sync_polltbl, &ptbl_rtcp, PIPE_RTCP);
#if RTPP_DEBUG_netio > 1
                RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld " \
                  "polling for %d RTCP file descriptors", \
                  last_ctick, ptbl_rtcp.curlen);
#endif
                nready_rtcp = poll(ptbl_rtcp.pfds, ptbl_rtcp.curlen, 0);
#if RTPP_DEBUG_netio
                if (RTPP_DEBUG_netio > 1 || nready_rtcp > 0) {
                    RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld " \
                      "polling for %d RTCP file descriptors: %d descriptors are ready", \
                      last_ctick, ptbl_rtcp.curlen, nready_rtcp);
                }
#endif
            }
#if RTPP_DEBUG_netio > 1
           RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld " \
              "polling for %d RTP file descriptors", \
              last_ctick, ptbl_rtp.curlen);
#endif
            nready_rtp = poll(ptbl_rtp.pfds, ptbl_rtp.curlen, 0);
#if RTPP_DEBUG_netio
            if (RTPP_DEBUG_netio > 1 || nready_rtp > 0) {
                RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld " \
                  "polling for RTP %d file descriptors: %d descriptors are ready", \
                  last_ctick, ptbl_rtp.curlen, nready_rtp);
            }
#endif
            if (nready_rtp < 0 && errno == EINTR) {
                tp[0] = getdtime();
                continue;
            }
        }

        tp[2] = getdtime();

        sender = rtpp_anetio_pick_sender(proc_cf->op);
        if (nready_rtp > 0) {
            process_rtp_only(cf, &ptbl_rtp, tp[2], ndrain, sender, rstats);
        }
        if (nready_rtcp > 0 && rtp_only == 0) {
            process_rtp_only(cf, &ptbl_rtcp, tp[2], ndrain, sender, rstats);
        }
        if (alarm_tick != 0) {
            rtpp_proc_ttl(cf->stable->sessions_ht, cf->stable->sessions_wrt,
              cf->stable->rtpp_notify_cf, cf->stable->rtpp_stats);
        }

        if (CALL_METHOD(cf->stable->servers_wrt, get_length) > 0) {
            rtpp_proc_servers(cf, tp[2], sender, rstats);
        }

        rtpp_anetio_pump_q(sender);
        tp[3] = getdtime();
        flush_rstats(stats_cf, rstats);

#if RTPP_DEBUG_timers
        recfilter_apply(&proc_cf->sleep_time, tp[1] - tp[0]);
        recfilter_apply(&proc_cf->poll_time, tp[2] - tp[1]);
        recfilter_apply(&proc_cf->proc_time, tp[3] - tp[2]);
#endif
        tp[0] = tp[3];
#if RTPP_DEBUG_timers
        if (last_ctick % (unsigned int)cf->stable->target_pfreq == 0 || last_ctick < 1000) {
#if 0
            RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld eptime %f, CSV: %f,%f,%f", \
              last_ctick, tp[3], (double)last_ctick / cf->stable->target_pfreq, tp[3] - tp[1], tp[3]);
#endif
            RTPP_LOG(cf->stable->glog, RTPP_LOG_DBUG, "run %lld eptime %f sleep_time %f poll_time %f proc_time %f CSV: %f,%f,%f,%f", \
              last_ctick, tp[3], proc_cf->sleep_time.lastval, proc_cf->poll_time.lastval, proc_cf->proc_time.lastval, \
              (double)last_ctick / cf->stable->target_pfreq, proc_cf->sleep_time.lastval, proc_cf->poll_time.lastval, proc_cf->proc_time.lastval);
        }
#endif
        prdic_procrastinate(proc_cf->elp);
#if RTPP_DEBUG_timers || RTPP_DEBUG_netio
        last_ctick++;
#endif
    }
    rtpp_polltbl_free(&ptbl_rtp);
    rtpp_polltbl_free(&ptbl_rtcp);
}

struct rtpp_proc_async *
rtpp_proc_async_ctor(struct cfg *cf)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = rtpp_zmalloc(sizeof(*proc_cf));
    if (proc_cf == NULL)
        return (NULL);

    init_rstats(cf->stable->rtpp_stats, &proc_cf->rstats);

#if RTPP_DEBUG_timers
    recfilter_init(&proc_cf->sleep_time, 0.999, 0.0, 0);
    recfilter_init(&proc_cf->poll_time, 0.999, 0.0, 0);
    recfilter_init(&proc_cf->proc_time, 0.999, 0.0, 0);
#endif

    proc_cf->op = rtpp_netio_async_init(cf, 1);
    if (proc_cf->op == NULL) {
        goto e0;
    }

    proc_cf->cf_save = cf;

    if (pthread_mutex_init(&proc_cf->tstate_lock, NULL) != 0) {
        goto e1;
    }
    proc_cf->elp = prdic_init(cf->stable->target_pfreq, cf->stable->sched_offset);
    if (proc_cf->elp == NULL) {
        goto e2;
    }

    if (pthread_create(&proc_cf->thread_id, NULL, (void *(*)(void *))&rtpp_proc_async_run, proc_cf) != 0) {
        goto e3;
    }
    proc_cf->pub.dtor = &rtpp_proc_async_dtor;
    return (&proc_cf->pub);

e3:
    prdic_free(proc_cf->elp);
e2:
    pthread_mutex_destroy(&proc_cf->tstate_lock);
e1:
    rtpp_netio_async_destroy(proc_cf->op);
e0:
    free(proc_cf);
    return (NULL);
}

static void
rtpp_proc_async_dtor(struct rtpp_proc_async *pub)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = PUB2PVT(pub);
    pthread_mutex_lock(&proc_cf->tstate_lock);
    assert(proc_cf->tstate == TSTATE_RUN);
    proc_cf->tstate = TSTATE_CEASE;
    pthread_mutex_unlock(&proc_cf->tstate_lock);
    pthread_join(proc_cf->thread_id, NULL);
    pthread_mutex_destroy(&proc_cf->tstate_lock);
    prdic_free(proc_cf->elp);
    rtpp_netio_async_destroy(proc_cf->op);
    free(proc_cf);
}
