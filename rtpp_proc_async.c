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
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "rtpp_log.h"
#include "rtpp_defines.h"
#include "rtpp_command_async.h"
#include "rtpp_netio_async.h"
#include "rtpp_proc.h"
#include "rtpp_proc_async.h"
#include "rtpp_queue.h"
#include "rtpp_wi.h"
#include "rtpp_util.h"

struct rtpp_proc_async_cf {
    pthread_t thread_id;
    int clock_tick;
    long long ncycles_ref;
    struct rtpp_anetio_cf *op;
    struct rtpp_queue *time_q;
};

struct sign_arg {
    int clock_tick;
    long long ncycles_ref;
};

static void
rtpp_proc_async_run(void *arg)
{
    struct cfg *cf;
    double eptime, last_tick_time;
    int alarm_tick, i, last_ctick, ndrain, rtp_only;
    struct rtpp_proc_async_cf *proc_cf;
    long long ncycles_ref, ncycles_ref_pre;
    double sptime;
    struct sign_arg *s_a;
    struct rtpp_wi *wi, *wis[10];
    struct sthread_args *sender;

    cf = (struct cfg *)arg;
    proc_cf = cf->stable.rtpp_proc_cf;

    last_tick_time = 0;
    wi = rtpp_queue_get_item(proc_cf->time_q, 0);
    s_a = (struct sign_arg *)rtpp_wi_sgnl_get_data(wi, NULL);
    last_ctick = s_a->clock_tick;
    ncycles_ref_pre = s_a->ncycles_ref;
    rtpp_wi_free(wi);

    for (;;) {
        i = rtpp_queue_get_items(proc_cf->time_q, wis, 10, 0);
        if (i <= 0) {
            continue;
        }
        i -= 1;
        s_a = (struct sign_arg *)rtpp_wi_sgnl_get_data(wis[i], NULL);
        last_ctick = s_a->clock_tick;
        ndrain = (s_a->ncycles_ref - ncycles_ref) / (POLL_RATE / MAX_RTP_RATE);
        ncycles_ref_pre = ncycles_ref;
        ncycles_ref = s_a->ncycles_ref;
        for(; i > -1; i--) {
            rtpp_wi_free(wis[i]);
        }

        sptime = getdtime();
#if RTPP_DEBUG
        if (last_ctick % POLL_RATE == 0 || last_ctick < 1000) {
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable.glog, "run %lld sptime %f, CSV: %f,%f,%f", \
              last_ctick, sptime, (double)last_ctick / (double)POLL_RATE, \
              ((double)ncycles_ref * cf->stable.target_runtime) - sptime, sptime);
        }
#endif

        if (ndrain < 1) {
            ndrain = 1;
        }

#if RTPP_DEBUG
        if (ndrain > 1) {
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable.glog, "run %lld " \
              "ncycles_ref %lld, ncycles_ref_pre %lld, ndrain %d CSV: %f,%f,%d", \
              last_ctick, ncycles_ref, ncycles_ref_pre, ndrain, \
              (double)last_ctick / (double)POLL_RATE, ndrain);
        }
#endif

        if (last_tick_time == 0 || last_tick_time > sptime) {
            alarm_tick = 0;
            last_tick_time = sptime;
        } else if (last_tick_time + TIMETICK < sptime) {
            alarm_tick = 1;
            last_tick_time = sptime;
        } else {
            alarm_tick = 0;
        }

        if (alarm_tick || (ncycles_ref % 7) == 0) {
            rtp_only = 0;
        } else {
            rtp_only = 1;
        }

        pthread_mutex_lock(&cf->sessinfo.lock);
        if (cf->sessinfo.nsessions > 0) {
            if (rtp_only == 0) {
                i = poll(cf->sessinfo.pfds_all, cf->sessinfo.nsessions, 0);
            } else {
                i = poll(cf->sessinfo.pfds_rtp, cf->sessinfo.nsessions / 2, 0);
            }
            pthread_mutex_unlock(&cf->sessinfo.lock);
            if (i < 0 && errno == EINTR) {
                eptime = getdtime();
                rtpp_command_async_wakeup(cf->stable.rtpp_cmd_cf, last_ctick, eptime - sptime);
                continue;
            }
        } else {
            pthread_mutex_unlock(&cf->sessinfo.lock);
        }

        eptime = getdtime();

        sender = rtpp_anetio_pick_sender(proc_cf->op);
        if (rtp_only == 0) {
            pthread_mutex_lock(&cf->glock);
            process_rtp(cf, eptime, alarm_tick, ndrain, sender);
        } else {
            process_rtp_only(cf, eptime, ndrain, sender);
            pthread_mutex_lock(&cf->glock);
        }
        if (cf->rtp_nsessions > 0) {
            process_rtp_servers(cf, eptime, sender);
        }
        pthread_mutex_unlock(&cf->glock);
        rtpp_anetio_pump_q(sender);
        eptime = getdtime();
        rtpp_command_async_wakeup(cf->stable.rtpp_cmd_cf, last_ctick, eptime - sptime);

#if RTPP_DEBUG
        if (last_ctick % POLL_RATE == 0 || last_ctick < 1000) {
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable.glog, "run %lld eptime %f, CSV: %f,%f,%f", \
              last_ctick, eptime, (double)last_ctick / (double)POLL_RATE, eptime - sptime, eptime);
        }
#endif
    }

}

void
rtpp_proc_async_wakeup(struct rtpp_proc_async_cf *proc_cf, int clock, long long ncycles_ref)
{
    struct sign_arg s_a;
    struct rtpp_wi *wi;

    s_a.clock_tick = clock;
    s_a.ncycles_ref = ncycles_ref;
    wi = rtpp_wi_malloc_sgnl(SIGALRM, &s_a, sizeof(s_a));
    if (wi == NULL) {
        /* XXX complain */
        return;
    }
    rtpp_queue_put_item(wi, proc_cf->time_q);
}

int
rtpp_proc_async_init(struct cfg *cf)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = malloc(sizeof(*proc_cf));
    if (proc_cf == NULL)
        return (-1);

    memset(proc_cf, '\0', sizeof(*proc_cf));

    proc_cf->time_q = rtpp_queue_init(1, "RTP_PROC(time)");
    if (proc_cf->time_q == NULL) {
        free(proc_cf);
        return (-1);
    }

    proc_cf->op = rtpp_netio_async_init(cf, 10);
    if (proc_cf->op == NULL) {
        rtpp_queue_destroy(proc_cf->time_q);
        free(proc_cf);
        return (-1);
    }

    cf->stable.rtpp_proc_cf = proc_cf;
    if (pthread_create(&proc_cf->thread_id, NULL, (void *(*)(void *))&rtpp_proc_async_run, cf) != 0) {
        rtpp_queue_destroy(proc_cf->time_q);
        rtpp_netio_async_destroy(proc_cf->op);
        free(proc_cf);
        cf->stable.rtpp_proc_cf = NULL;
        return (-1);
    }

    return (0);
}
