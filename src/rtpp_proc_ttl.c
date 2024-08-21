/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <elperiodic.h>

#include "config.h"

#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_notify.h"
#include "rtpp_session.h"
#include "rtpp_stats.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_proc_ttl.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"
#include "rtpp_pipe.h"
#include "rtpp_timeout_data.h"
#include "rtpp_locking.h"
#include "rtpp_threads.h"

struct foreach_args {
    struct rtpp_notify *rtpp_notify_cf;
    struct rtpp_stats *rtpp_stats;
    struct rtpp_weakref *sessions_wrt;
};

struct rtpp_proc_ttl_pvt {
    struct rtpp_proc_ttl pub;
    pthread_t thread_id;
    struct rtpp_anetio_cf *op;
    _Atomic(int) tstate;
    void *elp;
    struct rtpp_hash_table *sessions_ht;
    struct foreach_args fa;
};

static void rtpp_proc_ttl(struct rtpp_hash_table *, const struct foreach_args *);

static const char *notyfy_type = "timeout";

static int
rtpp_proc_ttl_foreach(void *dp, void *ap)
{
    const struct foreach_args *fap;
    const struct rtpp_session *sp;

    fap = (const struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (const struct rtpp_session *)dp;

    if (CALL_SMETHOD(sp->rtp, get_ttl) == 0) {
        RTPP_LOG(sp->log, RTPP_LOG_INFO, "session timeout");
        if (sp->timeout_data != NULL) {
            CALL_METHOD(fap->rtpp_notify_cf, schedule,
              sp->timeout_data->notify_target, sp->timeout_data->notify_tag,
              notyfy_type);
        }
        CALL_SMETHOD(fap->rtpp_stats, updatebyname, "nsess_timeout", 1);
        CALL_SMETHOD(fap->sessions_wrt, unreg, sp->seuid);
        return (RTPP_HT_MATCH_DEL);
    } else {
        CALL_SMETHOD(sp->rtp, decr_ttl);
    }
    return (RTPP_HT_MATCH_CONT);
}

static void
rtpp_proc_ttl(struct rtpp_hash_table *sessions_ht, const struct foreach_args *fap)
{

    CALL_SMETHOD(sessions_ht, foreach, rtpp_proc_ttl_foreach, (void *)fap, NULL);
}

static void
rtpp_proc_ttl_run(void *arg)
{
    struct rtpp_proc_ttl_pvt *proc_cf;
    int tstate;

    proc_cf = (struct rtpp_proc_ttl_pvt *)arg;

    for (;;) {
        tstate = atomic_load(&proc_cf->tstate);
        if (tstate == TSTATE_CEASE) {
            break;
        }
        prdic_procrastinate(proc_cf->elp);
        rtpp_proc_ttl(proc_cf->sessions_ht, &proc_cf->fa);
    }
}

static void
rtpp_proc_ttl_dtor(struct rtpp_proc_ttl *pub)
{
    struct rtpp_proc_ttl_pvt *proc_cf;
    int tstate;

    PUB2PVT(pub, proc_cf);
    tstate = atomic_load(&proc_cf->tstate);
    assert(tstate == TSTATE_RUN);
    atomic_store(&proc_cf->tstate, TSTATE_CEASE);
    pthread_join(proc_cf->thread_id, NULL);
    RTPP_OBJ_DECREF(proc_cf->sessions_ht);
    RTPP_OBJ_DECREF(proc_cf->fa.sessions_wrt);
    RTPP_OBJ_DECREF(proc_cf->fa.rtpp_notify_cf);
    RTPP_OBJ_DECREF(proc_cf->fa.rtpp_stats);
    prdic_free(proc_cf->elp);
    free(proc_cf);
}

struct rtpp_proc_ttl *
rtpp_proc_ttl_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_proc_ttl_pvt *proc_cf;

    proc_cf = rtpp_zmalloc(sizeof(*proc_cf));
    if (proc_cf == NULL)
        return (NULL);

    proc_cf->elp = prdic_init(1.0, 0.0);
    if (proc_cf->elp == NULL) {
        goto e0;
    }

    proc_cf->fa.rtpp_notify_cf = cfsp->rtpp_notify_cf;
    RTPP_OBJ_INCREF(cfsp->rtpp_notify_cf);
    proc_cf->fa.rtpp_stats = cfsp->rtpp_stats;
    RTPP_OBJ_INCREF(cfsp->rtpp_stats);
    proc_cf->fa.sessions_wrt = cfsp->sessions_wrt;
    RTPP_OBJ_INCREF(cfsp->sessions_wrt);
    proc_cf->sessions_ht = cfsp->sessions_ht;
    RTPP_OBJ_INCREF(cfsp->sessions_ht);

    if (pthread_create(&proc_cf->thread_id, NULL, (void *(*)(void *))&rtpp_proc_ttl_run, proc_cf) != 0) {
        goto e1;
    }
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(proc_cf->thread_id, "rtpp_proc_ttl");
#endif
    proc_cf->pub.dtor = &rtpp_proc_ttl_dtor;
    return (&proc_cf->pub);
e1:
    RTPP_OBJ_DECREF(cfsp->rtpp_stats);
    RTPP_OBJ_DECREF(cfsp->sessions_ht);
    RTPP_OBJ_DECREF(cfsp->sessions_wrt);
    RTPP_OBJ_DECREF(cfsp->rtpp_notify_cf);
    prdic_free(proc_cf->elp);
e0:
    free(proc_cf);
    return (NULL);
}
