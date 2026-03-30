/*
 * Copyright (c) 2026 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_wref.h"
#include "rtpp_wref_fin.h"

struct rtpp_wref_priv {
    struct rtpp_wref pub;
    struct rtpp_wref_target target;
    _Atomic(int) cnt;
};

static void rtpp_wref_dtor(struct rtpp_wref_priv *);
static int rtpp_wref_setref(struct rtpp_wref *, struct rtpp_refcnt *, void *);
static void rtpp_wref_inval(struct rtpp_wref *);
static const struct rtpp_wref_target *rtpp_wref_getref(struct rtpp_wref *);

DEFINE_SMETHODS(rtpp_wref,
    .setref = &rtpp_wref_setref,
    .getref = &rtpp_wref_getref,
);

struct rtpp_wref *
rtpp_wref_ctor(void)
{
    struct rtpp_wref_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    atomic_init(&pvt->cnt, 0);
    RTPP_DBGCODE() {
        PUBINST_FININIT(&pvt->pub, pvt, rtpp_wref_dtor);
    }
    return (&pvt->pub);
}

static void
rtpp_wref_dtor(struct rtpp_wref_priv *pvt)
{

    rtpp_wref_fin(&pvt->pub);
    RTPP_DBG_ASSERT(pvt->target.rco == NULL);
    RTPP_DBG_ASSERT(pvt->target.obj == NULL);
    RTPP_DBG_ASSERT(atomic_load_explicit(&pvt->cnt, memory_order_relaxed) == 0);
}

static int
rtpp_wref_setref(struct rtpp_wref *pub, struct rtpp_refcnt *target, void *obj)
{
    struct rtpp_wref_priv *pvt;
    int rval;

    PUB2PVT(pub, pvt);
    RTPP_DBG_ASSERT(pvt->target.rco == NULL);
    RTPP_DBG_ASSERT(atomic_load_explicit(&pvt->cnt, memory_order_relaxed) == 0);
    rval = CALL_SMETHOD(target, attach, (rtpp_refcnt_dtor_t)&rtpp_wref_inval,
      &pvt->pub);
    if (rval != 0) {
        return (-1);
    }
    atomic_store_explicit(&pvt->cnt, 1, memory_order_release);
    pvt->target = (struct rtpp_wref_target){.rco = target, .obj = obj};
    /*
     * Keep the weak reference object alive until the target invalidates it.
     */
    RTPP_OBJ_INCREF(&pvt->pub);
    return (0);
}

static void
rtpp_wref_inval(struct rtpp_wref *pub)
{
    struct rtpp_wref_priv *pvt;
    int expected, nspins = 0;

    PUB2PVT(pub, pvt);
    expected = 1;
    while (!atomic_compare_exchange_weak_explicit(&pvt->cnt, &expected, 0,
      memory_order_acq_rel, memory_order_acquire)) {
        RTPP_DBG_ASSERT(expected > 1);
        expected = 1;
        if (nspins == 40)
            sched_yield();
        else
            nspins += 1;
    }
    RTPP_DBGCODE() {
        pvt->target = (struct rtpp_wref_target){};
    }
    RTPP_OBJ_DECREF(pub);
}

static const struct rtpp_wref_target *
rtpp_wref_getref(struct rtpp_wref *pub)
{
    struct rtpp_wref_priv *pvt;
    int oldcnt;

    PUB2PVT(pub, pvt);
    oldcnt = atomic_fetch_add_explicit(&pvt->cnt, 1, memory_order_acq_rel);
    if (oldcnt == 0) {
        atomic_fetch_sub_explicit(&pvt->cnt, 1, memory_order_acq_rel);
        return (NULL);
    }
    RTPP_DBG_ASSERT(oldcnt >= 1);
    RTPP_DBG_ASSERT(pvt->target.rco != NULL);
    if (CALL_SMETHOD(pvt->target.rco, tryincref) == 0) {
        atomic_fetch_sub_explicit(&pvt->cnt, 1, memory_order_acq_rel);
        return (&pvt->target);
    }
    atomic_fetch_sub_explicit(&pvt->cnt, 1, memory_order_acq_rel);
    return (NULL);
}
