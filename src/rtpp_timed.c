/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_queue.h"
#include "rtpp_wi.h"
#include "rtpp_time.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_timed_fin.h"
#include "rtpp_timed_task_fin.h"

#include "elperiodic.h"

struct rtpp_timed_cf {
    struct rtpp_timed pub;
    struct rtpp_queue *q;
    struct rtpp_queue *cmd_q;
    double last_run;
    double period;
    pthread_t thread_id;
    struct rtpp_wi *sigterm;
    int wi_dsize;
    void *elp;
    int state;
};

#define RT_ST_RUNNING 0
#define RT_ST_SHTDOWN 1

struct rtpp_timed_wi {
    struct rtpp_timed_task pub;
    rtpp_timed_cb_t cb_func;
    rtpp_timed_cancel_cb_t cancel_cb_func;
    void *cb_func_arg;
    struct rtpp_refcnt *callback_rcnt;
    double when;
    double offset;
    struct rtpp_timed_cf *timed_cf;
    struct rtpp_wi *wi;
    void *rco[0];
};

#define PUB2PVT(pubp) \
  ((struct rtpp_timed_cf *)((char *)(pubp) - \
  offsetof(struct rtpp_timed_cf, pub)))

#define TASKPUB2PVT(pubp) \
  ((struct rtpp_timed_wi *)((char *)(pubp) - \
  offsetof(struct rtpp_timed_wi, pub)))

static void rtpp_timed_destroy(struct rtpp_timed_cf *);
static int rtpp_timed_schedule(struct rtpp_timed *,
  double offset, rtpp_timed_cb_t, rtpp_timed_cancel_cb_t, void *);
static struct rtpp_timed_task *rtpp_timed_schedule_rc(struct rtpp_timed *,
  double offset, struct rtpp_refcnt *, rtpp_timed_cb_t, rtpp_timed_cancel_cb_t,
  void *);
static void rtpp_timed_process(struct rtpp_timed_cf *, double);
static int rtpp_timed_cancel(struct rtpp_timed_task *);
static void rtpp_timed_shutdown(struct rtpp_timed *);

static void rtpp_timed_task_dtor(struct rtpp_timed_wi *);

const struct rtpp_timed_smethods rtpp_timed_smethods = {
    .schedule = &rtpp_timed_schedule,
    .schedule_rc = rtpp_timed_schedule_rc,
    .shutdown = &rtpp_timed_shutdown
};

static void
rtpp_timed_queue_run(void *argp)
{
    struct rtpp_timed_cf *rtcp;
    struct rtpp_wi *wi;
    struct rtpp_timed_wi *wi_data;
    int signum;
    double ctime;

    rtcp = (struct rtpp_timed_cf *)argp;
    for (;;) {
        if (rtpp_queue_get_length(rtcp->cmd_q) > 0) {
            wi = rtpp_queue_get_item(rtcp->cmd_q, 0);
            signum = rtpp_wi_sgnl_get_signum(wi);
            rtpp_wi_free(wi);
            if (signum == SIGTERM) {
                break;
            }
        }
        ctime = getdtime();
        rtpp_timed_process(rtcp, ctime);
        prdic_procrastinate(rtcp->elp);
    }
    /* We are terminating, get rid of all requests */
    while (rtpp_queue_get_length(rtcp->q) > 0) {
        wi = rtpp_queue_get_item(rtcp->q, 1);
        wi_data = rtpp_wi_data_get_ptr(wi, rtcp->wi_dsize, rtcp->wi_dsize);
        if (wi_data->cancel_cb_func != NULL) {
            wi_data->cancel_cb_func(wi_data->cb_func_arg);
        }
        if (wi_data->callback_rcnt != NULL) {
            CALL_SMETHOD(wi_data->callback_rcnt, decref);
        }
        CALL_SMETHOD(wi_data->pub.rcnt, decref);
    }
    prdic_free(rtcp->elp);
}

struct rtpp_timed *
rtpp_timed_ctor(double run_period)
{
    struct rtpp_timed_cf *rtcp;

    rtcp = rtpp_rzmalloc(sizeof(struct rtpp_timed_cf), PVT_RCOFFS(rtcp));
    if (rtcp == NULL) {
        goto e0;
    }
    rtcp->q = rtpp_queue_init(0, "rtpp_timed(requests)");
    if (rtcp->q == NULL) {
        goto e1;
    }
    rtcp->cmd_q = rtpp_queue_init(1, "rtpp_timed(commands)");
    if (rtcp->cmd_q == NULL) {
        goto e2;
    }
    /*
     * Pre-allocate sigterm, so that we don't have any malloc() in
     * the destructor.
     */
    rtcp->sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (rtcp->sigterm == NULL) {
        goto e3;
    }
    rtcp->elp = prdic_init(1.0 / run_period, 0.0);
    if (rtcp->elp == NULL) {
        goto e4;
    }
    if (pthread_create(&rtcp->thread_id, NULL,
      (void *(*)(void *))&rtpp_timed_queue_run, rtcp) != 0) {
        goto e5;
    }
    rtcp->last_run = getdtime();
    rtcp->period = run_period;
    rtcp->wi_dsize = sizeof(struct rtpp_timed_wi) + rtpp_refcnt_osize();
    rtcp->pub.smethods = &rtpp_timed_smethods;
    CALL_SMETHOD(rtcp->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_timed_destroy,
      rtcp);
    return (&rtcp->pub);
e5:
    prdic_free(rtcp->elp);
e4:
    rtpp_wi_free(rtcp->sigterm);
e3:
    rtpp_queue_destroy(rtcp->cmd_q);
e2:
    rtpp_queue_destroy(rtcp->q);
e1:
    CALL_SMETHOD(rtcp->pub.rcnt, decref);
    free(rtcp);
e0:
    return (NULL);
}

static void
rtpp_timed_shutdown(struct rtpp_timed *self)
{
    struct rtpp_timed_cf *rtpp_timed_cf;

    rtpp_timed_cf = PUB2PVT(self);
    assert(rtpp_timed_cf->state == RT_ST_RUNNING);
    rtpp_queue_put_item(rtpp_timed_cf->sigterm, rtpp_timed_cf->cmd_q);
    pthread_join(rtpp_timed_cf->thread_id, NULL);
    while (rtpp_queue_get_length(rtpp_timed_cf->cmd_q) > 0) {
        rtpp_wi_free(rtpp_queue_get_item(rtpp_timed_cf->cmd_q, 0));
    }
    rtpp_timed_cf->state = RT_ST_SHTDOWN;
}

static void
rtpp_timed_destroy(struct rtpp_timed_cf *rtpp_timed_cf)
{

    if (rtpp_timed_cf->state == RT_ST_RUNNING) {
        rtpp_timed_shutdown(&rtpp_timed_cf->pub);
    }
    rtpp_timed_fin(&(rtpp_timed_cf->pub));
    rtpp_queue_destroy(rtpp_timed_cf->cmd_q);
    rtpp_queue_destroy(rtpp_timed_cf->q);
    free(rtpp_timed_cf);
}

static struct rtpp_timed_task *
rtpp_timed_schedule_base(struct rtpp_timed *pub, double offset,
  struct rtpp_refcnt *callback_rcnt, rtpp_timed_cb_t cb_func,
  rtpp_timed_cancel_cb_t cancel_cb_func, void *cb_func_arg,
  int support_cancel)
{
    struct rtpp_wi *wi;
    struct rtpp_timed_wi *wi_data;
    struct rtpp_timed_cf *rtpp_timed_cf;

    rtpp_timed_cf = (struct rtpp_timed_cf *)pub;
    
    wi = rtpp_wi_malloc_udata((void **)&wi_data, rtpp_timed_cf->wi_dsize);
    if (wi == NULL) {
        return (NULL);
    }
    memset(wi_data, '\0', rtpp_timed_cf->wi_dsize);
    wi_data->wi = wi;
    wi_data->pub.rcnt = rtpp_refcnt_ctor_pa(&wi_data->rco[0]);
    if (wi_data->pub.rcnt == NULL) {
        rtpp_wi_free(wi);
        return (NULL);
    }
    wi_data->cb_func = cb_func;
    wi_data->cancel_cb_func = cancel_cb_func;
    wi_data->cb_func_arg = cb_func_arg;
    wi_data->when = getdtime() + offset;
    wi_data->offset = offset;
    wi_data->callback_rcnt = callback_rcnt;
    if (callback_rcnt != NULL) {
        CALL_SMETHOD(callback_rcnt, incref);
    }
    if (support_cancel != 0) {
        wi_data->pub.cancel = &rtpp_timed_cancel;
        wi_data->timed_cf = rtpp_timed_cf;
        CALL_SMETHOD(pub->rcnt, incref);
    }
    CALL_SMETHOD(wi_data->pub.rcnt, incref);
    rtpp_queue_put_item(wi, rtpp_timed_cf->q);
    CALL_SMETHOD(wi_data->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_timed_task_dtor,
      wi_data);
    return (&(wi_data->pub));
}

static struct rtpp_timed_task *
rtpp_timed_schedule_rc(struct rtpp_timed *pub, double offset,
  struct rtpp_refcnt *callback_rcnt, rtpp_timed_cb_t cb_func,
  rtpp_timed_cancel_cb_t cancel_cb_func, void *cb_func_arg)
{
    struct rtpp_timed_task *tpub;

    tpub = rtpp_timed_schedule_base(pub, offset, callback_rcnt, cb_func,
      cancel_cb_func, cb_func_arg, 1);
    if (tpub == NULL) {
        return (NULL);
    }
    return (tpub);
}

static int
rtpp_timed_schedule(struct rtpp_timed *pub, double offset,
  rtpp_timed_cb_t cb_func, rtpp_timed_cancel_cb_t cancel_cb_func,
  void *cb_func_arg)
{
    struct rtpp_timed_task *tpub;

    tpub = rtpp_timed_schedule_base(pub, offset, NULL, cb_func, cancel_cb_func,
      cb_func_arg, 0);
    if (tpub == NULL) {
        return (-1);
    }
    CALL_SMETHOD(tpub->rcnt, decref);
    return (0);
}

struct rtpp_timed_istime_arg {
    double ctime;
    int wi_dsize;
};

static int
rtpp_timed_istime(struct rtpp_wi *wi, void *p)
{
    struct rtpp_timed_istime_arg *ap;
    struct rtpp_timed_wi *wi_data;

    ap = (struct rtpp_timed_istime_arg *)p;
    wi_data = rtpp_wi_data_get_ptr(wi, ap->wi_dsize, ap->wi_dsize);
    if (wi_data->when <= ap->ctime) {
       return (0);
    }
    return (1);
}

static void
rtpp_timed_process(struct rtpp_timed_cf *rtcp, double ctime)
{
    struct rtpp_wi *wi;
    struct rtpp_timed_wi *wi_data;
    struct rtpp_timed_istime_arg istime_arg;
    enum rtpp_timed_cb_rvals cb_rval;

    istime_arg.ctime = ctime;
    istime_arg.wi_dsize = rtcp->wi_dsize;
    for (;;) {
        wi = rtpp_queue_get_first_matching(rtcp->q, rtpp_timed_istime,
          &istime_arg);
        if (wi == NULL) {
            return;
        }
        wi_data = rtpp_wi_data_get_ptr(wi, rtcp->wi_dsize, rtcp->wi_dsize);
        cb_rval = wi_data->cb_func(ctime, wi_data->cb_func_arg);
        if (cb_rval == CB_MORE) {
            while (wi_data->when <= ctime) {
                /* Make sure next run is in the future */
                wi_data->when += wi_data->offset;
            }
            rtpp_queue_put_item(wi, rtcp->q);
            continue;
        }
        if (wi_data->callback_rcnt != NULL) {
            CALL_SMETHOD(wi_data->callback_rcnt, decref);
        }
        CALL_SMETHOD(wi_data->pub.rcnt, decref);
    }
}

struct rtpp_timed_match_wi_arg {
    int wi_dsize;
    struct rtpp_timed_wi *wi_data;
};

static int
rtpp_timed_match_wi(struct rtpp_wi *wia, void *p)
{
    struct rtpp_timed_match_wi_arg *ap;
    struct rtpp_timed_wi *wia_data;

    ap = (struct rtpp_timed_match_wi_arg *)p;
    wia_data = rtpp_wi_data_get_ptr(wia, ap->wi_dsize, ap->wi_dsize);
    if (wia_data == ap->wi_data) {
        return (0);
    }
    return (1);
}

static void
rtpp_timed_task_dtor(struct rtpp_timed_wi *wi_data)
{

    rtpp_timed_task_fin(&(wi_data->pub));
    if (wi_data->timed_cf != NULL) {
        CALL_SMETHOD(wi_data->timed_cf->pub.rcnt, decref);
    }
    rtpp_wi_free(wi_data->wi);
}

static int
rtpp_timed_cancel(struct rtpp_timed_task *taskpub)
{
    struct rtpp_wi *wim;
    struct rtpp_timed_cf *rtcp;
    struct rtpp_timed_match_wi_arg match_arg;
    struct rtpp_timed_wi *wi_data;

    wi_data = TASKPUB2PVT(taskpub);

    rtcp = wi_data->timed_cf;
    match_arg.wi_dsize = rtcp->wi_dsize;
    match_arg.wi_data = wi_data;
    wim = rtpp_queue_get_first_matching(rtcp->q, rtpp_timed_match_wi,
      &match_arg);
    if (wim == NULL) {
        return (0);
    }
    if (wi_data->cancel_cb_func != NULL) {
        wi_data->cancel_cb_func(wi_data->cb_func_arg);
    }
    if (wi_data->callback_rcnt != NULL) {
        CALL_SMETHOD(wi_data->callback_rcnt, decref);
    }
    CALL_SMETHOD(wi_data->pub.rcnt, decref);
    return (1);
}
