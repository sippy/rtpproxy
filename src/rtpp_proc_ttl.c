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
#include "rtpp_mallocs.h"
#include "rtpp_pipe.h"
#include "rtpp_timeout_data.h"
#include "rtpp_locking.h"

struct rtpp_proc_ttl_pvt {
    struct rtpp_proc_ttl pub;
    pthread_t thread_id;
    struct rtpp_anetio_cf *op;
    const struct rtpp_cfg *cfsp_save;
    atomic_int tstate;
    void *elp;
};

#define TSTATE_RUN   0x0
#define TSTATE_CEASE 0x1

static void rtpp_proc_ttl(struct rtpp_hash_table *, struct rtpp_weakref_obj *,
  struct rtpp_notify *, struct rtpp_stats *);

struct foreach_args {
    struct rtpp_notify *rtpp_notify_cf;
    struct rtpp_stats *rtpp_stats;
    struct rtpp_weakref_obj *sessions_wrt;
};  

static const char *notyfy_type = "timeout";

static int
rtpp_proc_ttl_foreach(void *dp, void *ap)
{
    struct foreach_args *fap;
    struct rtpp_session *sp;

    fap = (struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (struct rtpp_session *)dp;

    if (CALL_METHOD(sp->rtp, get_ttl) == 0) {
        RTPP_LOG(sp->log, RTPP_LOG_INFO, "session timeout");
        if (sp->timeout_data != NULL) {
            CALL_METHOD(fap->rtpp_notify_cf, schedule,
              sp->timeout_data->notify_target, sp->timeout_data->notify_tag,
              notyfy_type);
        }
        CALL_SMETHOD(fap->rtpp_stats, updatebyname, "nsess_timeout", 1);
        CALL_METHOD(fap->sessions_wrt, unreg, sp->seuid);
        return (RTPP_HT_MATCH_DEL);
    } else {
        CALL_METHOD(sp->rtp, decr_ttl);
    }
    return (RTPP_HT_MATCH_CONT);
}

static void
rtpp_proc_ttl(struct rtpp_hash_table *sessions_ht, struct rtpp_weakref_obj
  *sessions_wrt, struct rtpp_notify *rtpp_notify_cf, struct rtpp_stats
  *rtpp_stats)
{
    struct foreach_args fargs;

    fargs.rtpp_notify_cf = rtpp_notify_cf;
    fargs.rtpp_stats = rtpp_stats;
    fargs.sessions_wrt = sessions_wrt;
    CALL_METHOD(sessions_ht, foreach, rtpp_proc_ttl_foreach, &fargs);
}

static void
rtpp_proc_ttl_run(void *arg)
{
    const struct rtpp_cfg *cfsp;
    struct rtpp_proc_ttl_pvt *proc_cf;
    struct rtpp_stats *stats_cf;
    int tstate;

    proc_cf = (struct rtpp_proc_ttl_pvt *)arg;
    cfsp = proc_cf->cfsp_save;
    stats_cf = cfsp->rtpp_stats;

    for (;;) {
        tstate = atomic_load(&proc_cf->tstate);
        if (tstate == TSTATE_CEASE) {
            break;
        }
        prdic_procrastinate(proc_cf->elp);
        rtpp_proc_ttl(cfsp->sessions_ht, cfsp->sessions_wrt,
          cfsp->rtpp_notify_cf, stats_cf);
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

    proc_cf->cfsp_save = cfsp;

    proc_cf->elp = prdic_init(1.0, 0.0);
    if (proc_cf->elp == NULL) {
        goto e0;
    }

    if (pthread_create(&proc_cf->thread_id, NULL, (void *(*)(void *))&rtpp_proc_ttl_run, proc_cf) != 0) {
        goto e1;
    }
    proc_cf->pub.dtor = &rtpp_proc_ttl_dtor;
    return (&proc_cf->pub);
e1:
    prdic_free(proc_cf->elp);
e0:
    free(proc_cf);
    return (NULL);
}
