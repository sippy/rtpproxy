/*
 * Copyright (c) 2017-2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

#if defined(_RTPP_MEMDEB_H)
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"
#endif
#include "rtp_packet.h"
#include "rtpp_queue.h"
#include "rtpp_netaddr.h"
#include "rtpp_network.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_wi.h"
#include "rtpp_wi_data.h"
#include "rtpp_wi_pkt.h"
#include "rtpp_wi_sgnl.h"

#if defined(_RTPP_MEMDEB_H)
RTPP_MEMDEB_APP_STATIC;
#endif

struct test_data {
    uint64_t nitems;
    double runtime;
    atomic_bool done;
};

struct tests {
    struct test_data queue_p2c;
    struct test_data queue_b2b;
    struct test_data wi_malloc_udata;
    struct test_data wi_malloc_data;
    struct test_data wi_malloc_pkt;
};

struct thr_args {
    struct rtpp_stats *rsp;
    struct rtpp_queue *fqp;
    struct rtpp_queue *bqp;
    struct rtpp_wi *sigterm;
    int tick;
    struct test_data *tdp;
};

struct sgnl_pload {
    const char *cp;
    unsigned long long *answerp;
};

static const char *MLQ = "meaning of life?";

static void inline
taint(struct rtpp_wi *p) {

    asm volatile ("" : : "m" (*p));
}

const struct rtpc_reply_smethods *const rtpc_reply_smethods;

static enum rtpp_timed_cb_rvals
update_derived_stats(double dtime, void *argp)
{
    struct thr_args *tap;

    tap = (struct thr_args *)argp;
    CALL_SMETHOD(tap->rsp, update_derived, dtime);
    switch (tap->tick) {
    case 0:
        rtpp_queue_put_item(tap->sigterm, tap->fqp);
        break;

    case 1:
        rtpp_queue_put_item(tap->sigterm, tap->fqp);
        break;

    case 2:
        atomic_store(&tap->tdp->done, true);
        break;

    case 3:
        atomic_store(&tap->tdp->done, true);
        break;

    case 4:
        atomic_store(&tap->tdp->done, true);
        break;

    default:
        abort();
    }
    tap->tick++;
    return (CB_MORE);
}

static void
worker_run(void *argp)
{
    const struct thr_args *tap;
    struct rtpp_wi *wi;
    size_t dtl;
    struct sgnl_pload *tplp;
#if defined(RTPQ_CHECK_SEQ)
    int64_t wi_id, wi_id_prev;
#endif

    tap = (struct thr_args *)argp;
#if defined(RTPQ_CHECK_SEQ)
    wi_id_prev = -1;
#endif
    for (;;) {
        wi = rtpp_queue_get_item(tap->fqp, 0);
        if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
            break;
        }
#if defined(RTPQ_CHECK_SEQ)
        wi_id = *(int64_t *)rtpp_wi_data_get_ptr(wi, 0, 0);
        assert(wi_id > wi_id_prev);
#endif
        /* deallocate wi */
        RTPP_OBJ_DECREF(wi);
#if defined(RTPQ_CHECK_SEQ)
        wi_id_prev = wi_id;
#endif
    }
    tplp = (struct sgnl_pload *)rtpp_wi_sgnl_get_data(wi, &dtl);
    assert(dtl == sizeof(*tplp));
    assert(tplp->cp == MLQ);
    *tplp->answerp = 42;
    atomic_store(&tap->tdp->done, true);
}

static void
worker_run_b2b_batch(void *argp)
{
    const struct thr_args *tap;
    struct rtpp_wi *wi, *wis[100];
    int sigterm, nitems, i;
#if defined(RTPQ_CHECK_SEQ)
    int64_t wi_id, wi_id_prev;
#endif

    tap = (struct thr_args *)argp;
#if defined(RTPQ_CHECK_SEQ)
    wi_id_prev = -1;
#endif
    for (sigterm = 0; sigterm == 0;) {
        nitems = rtpp_queue_get_items(tap->fqp, wis, 100, 0);
        for (i = 0; i < nitems; i++) {
            wi = wis[i];
            if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
                sigterm = 1;
#if defined(RTPQ_CHECK_SEQ)
            } else {
                wi_id = *(int64_t *)rtpp_wi_data_get_ptr(wi, 0, 0);
                assert(wi_id > wi_id_prev);
                wi_id_prev = wi_id;
#endif
            }
            rtpp_queue_put_item(wi, tap->bqp);
        }
    }
}

#define RPRINT(trp, trn, pls) \
    printf("%s(%d): processed %llu items in %f sec, %f items/sec\n", trn, pls, (unsigned long long)(trp)->nitems, \
      (trp)->runtime, (double)(trp)->nitems / (trp)->runtime)

int
main(int argc, char **argv)
{
    int ecode, tsize, i;
    struct rtpp_timed *rtp;
    struct rtpp_timed_task *ttp;
    struct thr_args targs;
    struct tests tests;
    pthread_t thread_id;
    struct rtpp_wi *wi;
    void *wi_data;
    double stime;
    struct sgnl_pload tpl;
    unsigned long long answer;
#if defined(RTPQ_CHECK_SEQ)
    int64_t wi_id = 0x222222, wi_id_prev;
#endif

    memset(&targs, '\0', sizeof(targs));
    memset(&tests, '\0', sizeof(tests));
    atomic_init(&tests.queue_p2c.done, false);
    atomic_init(&tests.queue_b2b.done, false);
    atomic_init(&tests.wi_malloc_udata.done, false);
    atomic_init(&tests.wi_malloc_data.done, false);
    atomic_init(&tests.wi_malloc_pkt.done, false);

    tsize = 1256;
    if (argc > 1) {
        tsize = atoi(argv[1]);
#if defined(RTPQ_CHECK_SEQ)
        assert(tsize >= sizeof(int64_t));
#endif
    }

#if defined(_RTPP_MEMDEB_H)
    RTPP_MEMDEB_APP_INIT();
    if (rtpp_memdeb_selftest(MEMDEB_SYM) != 0) {
        errx(1, "MEMDEB self-test has failed");
        /* NOTREACHED */
    }
#endif
    ecode = 0;
    rtp = rtpp_timed_ctor(0.1);
    targs.rsp = rtpp_stats_ctor();
    targs.fqp = rtpp_queue_init(RTPQ_LARGE_CB_LEN, "perftest main->worker");
    targs.bqp = rtpp_queue_init(RTPQ_LARGE_CB_LEN, "perftest worker->main");
    tpl.cp = MLQ;
    tpl.answerp = &answer;
    targs.sigterm = rtpp_wi_malloc_sgnl(SIGTERM, &tpl, sizeof(tpl));
    targs.tdp = &tests.queue_p2c;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    if (pthread_create(&thread_id, NULL, (void *(*)(void *))&worker_run, &targs) != 0) {
        err(1, "pthread_create() failed");
        /* NOTREACHED */
    }

    stime = getdtime();
    do {
        wi = rtpp_wi_malloc_udata((void **)&wi_data, tsize);
#if defined(RTPQ_CHECK_SEQ)
        *(typeof(wi_id) *)wi_data = wi_id++;
#endif
        rtpp_queue_put_item(wi, targs.fqp);
        tests.queue_p2c.nitems++;
        if ((tests.queue_p2c.nitems % RTPQ_LARGE_CB_LEN) == 0) {
            while(rtpp_queue_get_length(targs.fqp) > RTPQ_LARGE_CB_LEN) {
#if HAVE_PTHREAD_YIELD
                pthread_yield();
#else
                sched_yield();
#endif
                if (atomic_load(&tests.queue_p2c.done))
                    break;
            }
        }
    } while(!atomic_load(&tests.queue_p2c.done));
    tests.queue_p2c.runtime = getdtime() - stime;
    CALL_METHOD(ttp, cancel);
    RTPP_OBJ_DECREF(ttp);
    pthread_join(thread_id, NULL);
    while (rtpp_queue_get_length(targs.fqp) > 0) {
        wi = rtpp_queue_get_item(targs.fqp, 0);
        RTPP_OBJ_DECREF(wi);
        tests.queue_p2c.nitems--;
    }
    RPRINT(&tests.queue_p2c, "rtpp_queue (p2c)", tsize);

    targs.tdp = &tests.queue_b2b;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    if (pthread_create(&thread_id, NULL, (void *(*)(void *))&worker_run_b2b_batch, &targs) != 0) {
        err(1, "pthread_create() failed");
        /* NOTREACHED */
    }

    stime = getdtime();
    for (i = 0; i < 1024; i++) {
        wi = rtpp_wi_malloc_udata((void **)&wi_data, tsize);
#if defined(RTPQ_CHECK_SEQ)
        *(typeof(wi_id) *)wi_data = wi_id++;
#endif
        rtpp_queue_put_item(wi, targs.fqp);
    }
#if defined(RTPQ_CHECK_SEQ)
    wi_id_prev = -1;
#endif
    do {
         wi = rtpp_queue_get_item(targs.bqp, 0);
#if defined(RTPQ_CHECK_SEQ)
         if (wi != targs.sigterm) {
             int64_t _wi_id;
             wi_data = rtpp_wi_data_get_ptr(wi, 0, 0);
             _wi_id = *(int64_t *)wi_data;
             assert(_wi_id > wi_id_prev);
             wi_id_prev = _wi_id;
             *(typeof(wi_id) *)wi_data = wi_id++;
         }
#endif
         rtpp_queue_put_item(wi, targs.fqp);
         tests.queue_b2b.nitems++;
    } while (wi != targs.sigterm);
    tests.queue_b2b.runtime = getdtime() - stime;
    CALL_METHOD(ttp, cancel);
    RTPP_OBJ_DECREF(ttp);
    pthread_join(thread_id, NULL);
    while (rtpp_queue_get_length(targs.fqp) > 0) {
        wi = rtpp_queue_get_item(targs.fqp, 0);
        RTPP_OBJ_DECREF(wi);
    }
    while (rtpp_queue_get_length(targs.bqp) > 0) {
        wi = rtpp_queue_get_item(targs.bqp, 0);
        RTPP_OBJ_DECREF(wi);
    }
    RPRINT(&tests.queue_b2b, "rtpp_queue (b2b)", tsize);

    targs.tdp = &tests.wi_malloc_udata;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    stime = getdtime();
    do {
        wi = rtpp_wi_malloc_udata((void **)&wi_data, tsize);
        taint(wi);
        RTPP_OBJ_DECREF(wi);
        tests.wi_malloc_udata.nitems++;
    } while(!atomic_load(&tests.wi_malloc_udata.done));
    tests.wi_malloc_udata.runtime = getdtime() - stime;
    RPRINT(&tests.wi_malloc_udata, "rtpp_wi(udata)", tsize);
    CALL_METHOD(ttp, cancel);
    RTPP_OBJ_DECREF(ttp);

    targs.tdp = &tests.wi_malloc_data;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    stime = getdtime();
    do {
        char fake_data[tsize];
        wi = rtpp_wi_malloc_data(fake_data, tsize);
        taint(wi);
        RTPP_OBJ_DECREF(wi);
        tests.wi_malloc_data.nitems++;
    } while(!atomic_load(&tests.wi_malloc_data.done));
    tests.wi_malloc_data.runtime = getdtime() - stime;
    RPRINT(&tests.wi_malloc_data, "rtpp_wi(data)", tsize);
    CALL_METHOD(ttp, cancel);
    RTPP_OBJ_DECREF(ttp);

    struct sockaddr_in someaddr = {.sin_family = AF_INET};

    struct rtpp_netaddr *na = rtpp_netaddr_ctor();
    CALL_SMETHOD(na, set, sstosa(&someaddr), sizeof(someaddr));
    targs.tdp = &tests.wi_malloc_pkt;
    ttp = CALL_SMETHOD(rtp, schedule_rc, 10.0, targs.rsp->rcnt, update_derived_stats, NULL, &targs);
    stime = getdtime();
    do {
        struct rtp_packet *pkt = rtp_packet_alloc();
        wi = rtpp_wi_malloc_pkt_na(-1, pkt, na, 1, NULL);
        taint(wi);
        RTPP_OBJ_DECREF(wi);
        tests.wi_malloc_pkt.nitems++;
    } while(!atomic_load(&tests.wi_malloc_pkt.done));
    tests.wi_malloc_pkt.runtime = getdtime() - stime;
    RPRINT(&tests.wi_malloc_pkt, "rtpp_wi_pkt()", tsize);
    CALL_METHOD(ttp, cancel);
    RTPP_OBJ_DECREF(ttp);
    RTPP_OBJ_DECREF(na);

    RTPP_OBJ_DECREF(targs.rsp);
    CALL_SMETHOD(rtp, shutdown);
    RTPP_OBJ_DECREF(rtp);
    wi = rtpp_wi_malloc_udata((void **)&wi_data, tsize);
    rtpp_queue_put_item(wi, targs.fqp);
    rtpp_queue_destroy(targs.fqp);
    wi = rtpp_wi_malloc_udata((void **)&wi_data, tsize);
    rtpp_queue_put_item(wi, targs.bqp);
    rtpp_queue_destroy(targs.bqp);

    assert(tpl.cp == MLQ);
    assert(answer == 42);

#if defined(_RTPP_MEMDEB_H)
    ecode = rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) == 0 ? 0 : 1;
#endif

    exit(ecode);
}
