/*
 * Copyright (c) 2023 Sippy Software, Inc., http://www.sippysoft.com
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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_yield() */
#endif
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"
#include "rtpp_time.h"
#include "rtpp_threads.h"
#include "rtpp_proc_async.h"
#include "rtpp_proc_wakeup_fin.h"
#include "rtpp_proc_wakeup.h"

#define MAX_WAKEUPS_PS 1000.0

struct rtpp_proc_wakeup_priv {
    struct rtpp_proc_wakeup pub;
    pthread_t thread_id;
    _Atomic(int) tstate;
    int requested_i_wake;
    int delivered_i_wake;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct {
        union {
            struct {
                int rtp;
                int rtcp;
            };
            int n[0];
        };
    } wakefds;
};

static void rtpp_proc_wakeup_dtor(struct rtpp_proc_wakeup_priv *);
static int rtpp_proc_wakeup_nudge(struct rtpp_proc_wakeup *);

DEFINE_SMETHODS(rtpp_proc_wakeup,
    .nudge = &rtpp_proc_wakeup_nudge,
);

static void
rtpp_proc_wakeup_run(void *arg)
{
    struct rtpp_proc_wakeup_priv *wtcp;
    int requested_i_wake = 0;
    double last_wakeup = 0, wakeup_at = 0;
    const double wakeup_ival = 1.0 / MAX_WAKEUPS_PS;

    wtcp = (struct rtpp_proc_wakeup_priv *)arg;

    atomic_store(&wtcp->tstate, TSTATE_RUN);
    for (;;) {
        MAYBE_UNUSED int ret;

        pthread_mutex_lock(&wtcp->mutex);
        while ((atomic_load(&wtcp->tstate) == TSTATE_RUN) && (requested_i_wake == wtcp->requested_i_wake)) {
            if (wakeup_at == 0) {
                pthread_cond_wait(&wtcp->cond, &wtcp->mutex);
            } else {
                struct timespec deadline;
                dtime2mtimespec(wakeup_at, &deadline);
                int rc = pthread_cond_timedwait(&wtcp->cond, &wtcp->mutex, &deadline);
                if (rc == ETIMEDOUT) {
                    requested_i_wake = wtcp->requested_i_wake;
                    goto deliver;
                }
            }
        }
        if (atomic_load(&wtcp->tstate) != TSTATE_RUN) {
            pthread_mutex_unlock(&wtcp->mutex);
            break;
        }

        requested_i_wake = wtcp->requested_i_wake;
        if (last_wakeup > 0 && (getdtime() - last_wakeup) < wakeup_ival) {
            wakeup_at = last_wakeup + wakeup_ival;
            pthread_mutex_unlock(&wtcp->mutex);
            continue;
        }
deliver:
        wtcp->delivered_i_wake = requested_i_wake;
        pthread_mutex_unlock(&wtcp->mutex);

        ret = write(wtcp->wakefds.rtp, &requested_i_wake,
          sizeof(requested_i_wake));
        RTPP_DBG_ASSERT(ret < 0 || ret == sizeof(requested_i_wake));
        ret = write(wtcp->wakefds.rtcp, &requested_i_wake,
          sizeof(requested_i_wake));
        RTPP_DBG_ASSERT(ret < 0 || ret == sizeof(requested_i_wake));
        last_wakeup = getdtime();
        wakeup_at = 0;
    }
}

struct rtpp_proc_wakeup *
rtpp_proc_wakeup_ctor(int rtp_wakefd, int rtcp_wakefd)
{
    pthread_condattr_t cond_attr;
    struct rtpp_proc_wakeup_priv *pvt;

    RTPP_DBG_ASSERT(rtp_wakefd > 0 && rtcp_wakefd > 0);
    pvt = rtpp_rzmalloc(sizeof(struct rtpp_proc_wakeup_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL)
        goto e0;
    if (pthread_mutex_init(&pvt->mutex, NULL) != 0)
        goto e1;
    if (pthread_condattr_init(&cond_attr) != 0)
        goto e2;
    if (pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) != 0)
        goto e3;
    if (pthread_cond_init(&pvt->cond, &cond_attr) != 0)
        goto e3;
    atomic_init(&pvt->tstate, TSTATE_CEASE);
    pvt->wakefds.rtp = rtp_wakefd;
    pvt->wakefds.rtcp = rtcp_wakefd;
    if (pthread_create(&pvt->thread_id, NULL, (void *(*)(void *))&rtpp_proc_wakeup_run, pvt) != 0)
        goto e4;
    pthread_condattr_destroy(&cond_attr);
    rtpp_proc_async_setprocname(pvt->thread_id, "IO_WKUP");
    while (atomic_load(&pvt->tstate) != TSTATE_RUN)
#if HAVE_PTHREAD_YIELD
        pthread_yield();
#else
        sched_yield();
#endif
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_proc_wakeup_dtor);
    return (&pvt->pub);
e4:
    pthread_cond_destroy(&pvt->cond);
e3:
    pthread_condattr_destroy(&cond_attr);
e2:
    pthread_mutex_destroy(&pvt->mutex);
e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
rtpp_proc_wakeup_dtor(struct rtpp_proc_wakeup_priv *pvt)
{

    rtpp_proc_wakeup_fin(&(pvt->pub));
    atomic_store(&pvt->tstate, TSTATE_CEASE);
    /* notify worker thread */
    rtpp_proc_wakeup_nudge(&(pvt->pub));
    pthread_join(pvt->thread_id, NULL);
    pthread_cond_destroy(&pvt->cond);
    pthread_mutex_destroy(&pvt->mutex);
}

static int
rtpp_proc_wakeup_nudge(struct rtpp_proc_wakeup *self)
{
    struct rtpp_proc_wakeup_priv *pvt;
    int requested_i_wake, delivered_i_wake;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->mutex);
    pvt->requested_i_wake += 1;
    requested_i_wake = pvt->requested_i_wake;
    delivered_i_wake = pvt->delivered_i_wake;
    /* notify worker thread */
    pthread_cond_signal(&pvt->cond);
    pthread_mutex_unlock(&pvt->mutex);
    return (requested_i_wake - delivered_i_wake);
}
