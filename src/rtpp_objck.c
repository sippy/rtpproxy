/*
 * Copyright (c) 2017 Sippy Software, Inc., http://www.sippysoft.com
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

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

#include "rtpp_types.h"
#if defined(_RTPP_MEMDEB_H)
#include "rtpp_memdeb_internal.h"
#endif
#include "rtpp_queue.h"
#include "rtpp_refcnt.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_wi.h"

#if defined(_RTPP_MEMDEB_H)
RTPP_MEMDEB_STATIC(rtpp_objck);
#endif

struct thr_args {
    struct rtpp_stats *rsp;
    struct rtpp_queue *rqp;
    struct rtpp_wi *sigterm;
    int done;
};

static enum rtpp_timed_cb_rvals
update_derived_stats(double dtime, void *argp)
{
    struct thr_args *tap;

    tap = (struct thr_args *)argp;
    CALL_SMETHOD(tap->rsp, update_derived, dtime);
    rtpp_queue_put_item(tap->sigterm, tap->rqp);
    tap->done = 1;
    return (CB_MORE);
}

static void
worker_run(void *argp)
{
    struct thr_args *tap;
    struct rtpp_wi *wi;

    tap = (struct thr_args *)argp;
    for (;;) {
        wi = rtpp_queue_get_item(tap->rqp, 0);
        if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
            rtpp_wi_free(wi);
            break;
        }
        /* deallocate wi */
        rtpp_wi_free(wi);
    }
}

int
main(int argc, char **argv)
{
    int ecode;
    struct rtpp_timed *rtp;
    struct rtpp_timed_task *ttp;
    struct thr_args targs;
    pthread_t thread_id;
    struct rtpp_wi *wi;
    void *wi_data;
    int nitems;
    double stime, etime;

#if defined(_RTPP_MEMDEB_H)
    RTPP_MEMDEB_INIT(rtpp_objck);
    if (rtpp_memdeb_selftest(_rtpp_objck_memdeb) != 0) {
        errx(1, "MEMDEB self-test has failed");
        /* NOTREACHED */
    }
#endif
    rtp = rtpp_timed_ctor(0.1);
    targs.rsp = rtpp_stats_ctor();
    targs.rqp = rtpp_queue_init(1, "perftest");
    targs.sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    targs.done = 0;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    if (pthread_create(&thread_id, NULL, (void *(*)(void *))&worker_run, &targs) != 0) {
        err(1, "pthread_create() failed");
        /* NOTREACHED */
    }
    nitems = 0;
    stime = getdtime();
    do {
        wi = rtpp_wi_malloc_udata((void **)&wi_data, 256);
        rtpp_queue_put_item(wi, targs.rqp);
        nitems++;
    } while(!targs.done);
    etime = getdtime();
    pthread_join(thread_id, NULL);
    CALL_SMETHOD(ttp->rcnt, decref);
    CALL_SMETHOD(targs.rsp->rcnt, decref);
    CALL_SMETHOD(rtp, shutdown);
    CALL_SMETHOD(rtp->rcnt, decref);
    while (rtpp_queue_get_length(targs.rqp) > 0) {
        wi = rtpp_queue_get_item(targs.rqp, 0);
        rtpp_wi_free(wi);
        nitems--;
    }
    rtpp_queue_destroy(targs.rqp);
    printf("Processed %d items, %f items/sec\n", nitems, (double)nitems / (etime - stime));

#if defined(_RTPP_MEMDEB_H)
    ecode = rtpp_memdeb_dumpstats(_rtpp_objck_memdeb, 0) == 0 ? 0 : 1;
#endif

    exit(ecode);
}
