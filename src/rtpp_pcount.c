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

#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_pcount.h"
#include "rtpp_pcount_fin.h"

struct _rtpps_pcount {
    atomic_ulong nrelayed;
    atomic_ulong ndropped;
    atomic_ulong nignored;
};

struct rtpp_pcount_priv {
    struct rtpp_pcount pub;
    struct _rtpps_pcount cnt;
};

static void rtpp_pcount_dtor(struct rtpp_pcount_priv *);
static void rtpp_pcount_reg_reld(struct rtpp_pcount *);
static void rtpp_pcount_reg_drop(struct rtpp_pcount *);
static void rtpp_pcount_reg_ignr(struct rtpp_pcount *);
static void rtpp_pcount_get_stats(struct rtpp_pcount *, struct rtpps_pcount *);

static const struct rtpp_pcount_smethods _rtpp_pcount_smethods = {
    .reg_reld = &rtpp_pcount_reg_reld,
    .reg_drop = &rtpp_pcount_reg_drop,
    .reg_ignr = &rtpp_pcount_reg_ignr,
    .get_stats = &rtpp_pcount_get_stats
};
const struct rtpp_pcount_smethods * const rtpp_pcount_smethods = &_rtpp_pcount_smethods;

struct rtpp_pcount *
rtpp_pcount_ctor(void)
{
    struct rtpp_pcount_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pcount_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = rtpp_pcount_smethods;
#endif
    atomic_init(&(pvt->cnt.nrelayed), 0);
    atomic_init(&(pvt->cnt.ndropped), 0);
    atomic_init(&(pvt->cnt.nignored), 0);
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pcount_dtor,
      pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_pcount_dtor(struct rtpp_pcount_priv *pvt)
{

    rtpp_pcount_fin(&(pvt->pub));
    free(pvt);
}

static void
rtpp_pcount_reg_reld(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    atomic_fetch_add_explicit(&pvt->cnt.nrelayed, 1, memory_order_relaxed);
}

static void
rtpp_pcount_reg_drop(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    PUB2PVT(self, pvt);
    atomic_fetch_add_explicit(&pvt->cnt.ndropped, 1, memory_order_relaxed);
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
