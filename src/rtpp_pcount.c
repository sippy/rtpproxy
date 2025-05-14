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
#include <stdatomic.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_codeptr.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_pcount.h"
#include "rtpp_pcount_fin.h"

struct _rtpps_pcount {
    _Atomic(unsigned long) nrelayed;
    _Atomic(unsigned long) ndropped;
    _Atomic(unsigned long) nignored;
};

#define TOP_DROPS_SIZE 4

struct rtpp_pcount_priv {
    struct rtpp_pcount pub;
    struct _rtpps_pcount cnt;
    struct {
        _Atomic(const struct rtpp_codeptr *) ptr;
        _Atomic(unsigned long) cnt;
    } top_drop_locs[TOP_DROPS_SIZE];
};

static void rtpp_pcount_dtor(struct rtpp_pcount_priv *);
static void rtpp_pcount_reg_reld(struct rtpp_pcount *);
static void rtpp_pcount_reg_drop(struct rtpp_pcount *, HERETYPE);
static void rtpp_pcount_reg_ignr(struct rtpp_pcount *);
static void rtpp_pcount_get_stats(struct rtpp_pcount *, struct rtpps_pcount *);
static void rtpp_pcount_log_drops(struct rtpp_pcount *, struct rtpp_log *);

DEFINE_SMETHODS(rtpp_pcount,
    .reg_reld = &rtpp_pcount_reg_reld,
    .reg_drop = &rtpp_pcount_reg_drop,
    .reg_ignr = &rtpp_pcount_reg_ignr,
    .get_stats = &rtpp_pcount_get_stats,
    .log_drops = &rtpp_pcount_log_drops
);

struct rtpp_pcount *
rtpp_pcount_ctor(void)
{
    struct rtpp_pcount_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pcount_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    atomic_init(&(pvt->cnt.nrelayed), 0);
    atomic_init(&(pvt->cnt.ndropped), 0);
    atomic_init(&(pvt->cnt.nignored), 0);
    for (int i = 0; i < TOP_DROPS_SIZE; i++) {
        atomic_init(&(pvt->top_drop_locs[i].ptr), NULL);
        atomic_init(&(pvt->top_drop_locs[i].cnt), 0);
    }
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_pcount_dtor);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_pcount_dtor(struct rtpp_pcount_priv *pvt)
{

    rtpp_pcount_fin(&(pvt->pub));
}

static void
rtpp_pcount_reg_reld(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    atomic_fetch_add_explicit(&pvt->cnt.nrelayed, 1, memory_order_relaxed);
}

static void
rtpp_pcount_reg_drop(struct rtpp_pcount *self, HERETYPEARG)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    atomic_fetch_add_explicit(&pvt->cnt.ndropped, 1, memory_order_relaxed);
    assert(mlp != NULL);
    for (int i = 0; i < TOP_DROPS_SIZE; i++) {
        const struct rtpp_codeptr *old_ptr;

retry:
        old_ptr = atomic_load_explicit(&pvt->top_drop_locs[i].ptr, memory_order_relaxed);
        if (old_ptr == NULL) {
            if (atomic_compare_exchange_strong(&pvt->top_drop_locs[i].ptr, &old_ptr, mlp) != true) {
                goto retry;
            }
        }
        if (old_ptr != NULL && old_ptr != mlp)
            continue;
        atomic_fetch_add_explicit(&pvt->top_drop_locs[i].cnt, 1, memory_order_relaxed);
        break;
    }
}

static void rtpp_pcount_log_drops(struct rtpp_pcount *self, struct rtpp_log *log)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    for (int i = 0; i < TOP_DROPS_SIZE; i++) {
        const struct rtpp_codeptr *mlp;
        unsigned long cnt;

        mlp = atomic_load_explicit(&pvt->top_drop_locs[i].ptr, memory_order_relaxed);
        if (mlp == NULL)
            break;
        cnt = atomic_load_explicit(&pvt->top_drop_locs[i].cnt, memory_order_relaxed);
        if (cnt == 0)
            continue;
        RTPP_LOG(log, RTPP_LOG_INFO, CODEPTR_FMT(": %lu packets dropped here", mlp, cnt));
    }
}


static void
rtpp_pcount_reg_ignr(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    atomic_fetch_add_explicit(&pvt->cnt.nignored, 1, memory_order_relaxed);
}

static void
rtpp_pcount_get_stats(struct rtpp_pcount *self, struct rtpps_pcount *ocnt)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    ocnt->nrelayed = atomic_load_explicit((&pvt->cnt.nrelayed), memory_order_relaxed);
    ocnt->ndropped = atomic_load_explicit((&pvt->cnt.ndropped), memory_order_relaxed);
    ocnt->nignored = atomic_load_explicit((&pvt->cnt.nignored), memory_order_relaxed);
}
