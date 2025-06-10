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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
/* Apparently needed for asprintf(3) */
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_refcnt_fin.h"

#if RTPP_DEBUG_refcnt
#include <stdio.h>
#ifdef RTPP_DEBUG
#include "rtpp_stacktrace.h"
#endif
#endif

static void rtpp_refcnt_incref(struct rtpp_refcnt *, HERETYPE);
static void rtpp_refcnt_decref(struct rtpp_refcnt *, HERETYPE);

/*
 * Somewhat arbitrary cap on the maximum value of the references. Just here
 * to catch any runaway situations, i.e. bugs in the code.
 */
#define RC_ABS_MAX 2000000

#define CACHE_SIZE 64

struct dtor_pair {
    rtpp_refcnt_dtor_t f;
    union {
        void *data;
        struct rtpp_refcnt *rcnt;
    };
};

struct rtpp_refcnt_priv
{
    struct rtpp_refcnt pub;
    _Atomic(int) cnt __attribute__((aligned(CACHE_SIZE)));
    struct {
        unsigned int shared:1;
#if RTPP_DEBUG_refcnt
        unsigned int trace:1;
#endif
    }  __attribute__((aligned(CACHE_SIZE)));
    int ulen;
    struct dtor_pair dtors[MAX_DTORS];
};
const size_t rtpp_refcnt_osize = sizeof(struct rtpp_refcnt_priv);

static void rtpp_refcnt_attach(struct rtpp_refcnt *, rtpp_refcnt_dtor_t,
  void *);
static void rtpp_refcnt_attach_rc(struct rtpp_refcnt *, struct rtpp_refcnt *);
static void *rtpp_refcnt_getdata(struct rtpp_refcnt *);

#if RTPP_DEBUG_refcnt
static void rtpp_refcnt_traceen(struct rtpp_refcnt *, HERETYPE);
static int rtpp_refcnt_peek(struct rtpp_refcnt *);
#endif

DEFINE_SMETHODS(rtpp_refcnt,
    .incref = &rtpp_refcnt_incref,
    .decref = &rtpp_refcnt_decref,
    .getdata = &rtpp_refcnt_getdata,
#if RTPP_DEBUG_refcnt
    .traceen = rtpp_refcnt_traceen,
    .peek = rtpp_refcnt_peek,
#endif
    .attach = &rtpp_refcnt_attach,
    .attach_rc = &rtpp_refcnt_attach_rc,
);

#if defined(RTPP_CHECK_LEAKS)
static void
rtpp_refcnt_free(void *p)
{

    free(p);
}
#endif

#define DTOR_PAIR_INIT(fn, fd) (struct dtor_pair){.f=(fn), .data=(fd)}
#define DTOR_RC_INIT(rc) (struct dtor_pair){.rcnt=(rc)}

struct rtpp_refcnt *
rtpp_refcnt_ctor(void *data, rtpp_refcnt_dtor_t dtor_f)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_refcnt_priv));
    if (pvt == NULL) {
        return (NULL);
    }
#if !defined(RTPP_CHECK_LEAKS)
    pvt->dtors[0] = DTOR_PAIR_INIT(free, pvt);
#else
    pvt->dtors[0] = DTOR_PAIR_INIT(rtpp_refcnt_free, pvt);
#endif
    if (dtor_f != NULL) {
        pvt->dtors[1] = DTOR_PAIR_INIT(dtor_f, data);
        pvt->ulen = 1;
    } else if (data != NULL) {
#if !defined(RTPP_CHECK_LEAKS)
        pvt->dtors[1] = DTOR_PAIR_INIT(free, data);
#else
        pvt->dtors[1] = DTOR_PAIR_INIT(rtpp_refcnt_free, data);
#endif
        pvt->ulen = 1;
    }
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = rtpp_refcnt_smethods;
#endif
    return (&pvt->pub);
}

struct rtpp_refcnt *
rtpp_refcnt_ctor_pa(void *pap, void *data)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pap;
    if (data != NULL) {
#if !defined(RTPP_CHECK_LEAKS)
        pvt->dtors[0] = DTOR_PAIR_INIT(free, data);
#else
        pvt->dtors[0] = DTOR_PAIR_INIT(rtpp_refcnt_free, data);
#endif
    } else {
        pvt->ulen = -1;
    }
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = rtpp_refcnt_smethods;
#endif
    return (&pvt->pub);
}

static void
rtpp_refcnt_attach(struct rtpp_refcnt *pub, rtpp_refcnt_dtor_t dtor_f,
  void *data)
{
    struct rtpp_refcnt_priv *pvt;

    PUB2PVT(pub, pvt);
    RTPP_DBG_ASSERT(MAX_DTORS > pvt->ulen);
    pvt->ulen += 1;
    pvt->dtors[pvt->ulen] = DTOR_PAIR_INIT(dtor_f, data);
}

static void
rtpp_refcnt_attach_rc(struct rtpp_refcnt *pub, struct rtpp_refcnt *other)
{
    struct rtpp_refcnt_priv *pvt;

    PUB2PVT(pub, pvt);
    RTPP_DBG_ASSERT(MAX_DTORS > pvt->ulen);
    pvt->ulen += 1;
    pvt->dtors[pvt->ulen] = DTOR_RC_INIT(other);
}

static void
rtpp_refcnt_incref(struct rtpp_refcnt *pub, HERETYPE mlp)
{
    struct rtpp_refcnt_priv *pvt;
    MAYBE_UNUSED int oldcnt;

    PUB2PVT(pub, pvt);
    RTPP_DBGCODE() {
        oldcnt = atomic_load_explicit(&pvt->cnt, memory_order_relaxed) + 1;
        RTPP_DBG_ASSERT(oldcnt > 0 && oldcnt < RC_ABS_MAX);
    }
    if (pvt->shared) {
        oldcnt = atomic_fetch_add_explicit(&pvt->cnt, 1, memory_order_relaxed) + 1;
    } else {
        oldcnt = 1;
        pvt->shared = 1;
        atomic_store_explicit(&pvt->cnt, 1, memory_order_release);
    }
#if RTPP_DEBUG_refcnt
    if (pvt->trace == 1) {
#ifdef RTPP_DEBUG
        char *dbuf;
        rtpp_memdeb_asprintf(&dbuf, MEMDEB_SYM, mlp,
          CODEPTR_FMT(": rtpp_refcnt(%p, %u).incref()", mlp, pub, oldcnt));
        if (dbuf != NULL) {
            rtpp_stacktrace_print(dbuf);
            free(dbuf);
        }
#else
        fprintf(stderr, CODEPTR_FMT(": rtpp_refcnt(%p, %u).incref()\n", mlp, pub, oldcnt));
#endif
    }
#endif
    RTPP_DBG_ASSERT(oldcnt > 0);
}

static void
rtpp_refcnt_decref(struct rtpp_refcnt *pub, HERETYPE mlp)
{
    struct rtpp_refcnt_priv *pvt;
    int oldcnt;

    PUB2PVT(pub, pvt);
    RTPP_DBGCODE() {
        oldcnt = atomic_load_explicit(&pvt->cnt, memory_order_relaxed) + 1;
        RTPP_DBG_ASSERT(oldcnt > 0 && oldcnt < RC_ABS_MAX);
    }
#if RTPP_DEBUG_refcnt
    /*
     * Fetch flags before decrement, otherwise we can decrement and then
     * somebody decrements it and deallocates. Atomic is not needed since
     * this initialized at the init time.
     */
    unsigned int trace = pvt->trace;
#endif
    if (pvt->shared) {
        oldcnt = atomic_fetch_sub_explicit(&pvt->cnt, 1, memory_order_release) + 1;
    } else {
        oldcnt = 1;
    }
#if RTPP_DEBUG_refcnt
    if (trace) {
#ifdef RTPP_DEBUG
        char *dbuf;
        rtpp_memdeb_asprintf(&dbuf, MEMDEB_SYM, mlp,
          CODEPTR_FMT(": rtpp_refcnt(%p, %u).decref()", mlp, pub, oldcnt));
        if (dbuf != NULL) {
            rtpp_stacktrace_print(dbuf);
            free(dbuf);
        }
#else
        fprintf(stderr, CODEPTR_FMT(": rtpp_refcnt(%p, %u).decref()\n", mlp, pub, oldcnt));
#endif
    }
#endif
    RTPP_DBG_ASSERT(oldcnt > 0);
    if (oldcnt == 1) {
        if (pvt->shared) {
            atomic_thread_fence(memory_order_acquire);
        }
        for (int i = pvt->ulen; i >= 0; i--) {
            struct dtor_pair *dp = &pvt->dtors[i];
#if RTPP_DEBUG_refcnt
            if (trace) {
                Dl_info info;
                if (dladdr(dp->f, &info) && info.dli_sname != NULL)
                    fprintf(stderr, "calling destructor %s@<%p>(%p)\n", info.dli_sname,
                      dp->f, dp->data);
                else
                    fprintf(stderr, "calling destructor @<%p>(%p)\n", dp->f, dp->data);
            }
#endif
            if (i == 0)
                rtpp_refcnt_fin(pub);
            if (dp->f != NULL) {
                dp->f(dp->data);
            } else {
                struct rtpp_refcnt *other = dp->rcnt;
                rtpp_refcnt_decref(other, mlp);
            }
        }
    }
}

static void *
rtpp_refcnt_getdata(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    PUB2PVT(pub, pvt);
    RTPP_DBG_ASSERT(atomic_load(&pvt->cnt) >= 0 && pvt->ulen >= 0);
    return (pvt->dtors[0].data);
}

#if RTPP_DEBUG_refcnt
static void
rtpp_refcnt_traceen(struct rtpp_refcnt *pub, HERETYPE mlp)
{
    struct rtpp_refcnt_priv *pvt;

    PUB2PVT(pub, pvt);
    pvt->trace = 1;
    int oldcnt = atomic_load_explicit(&pvt->cnt, memory_order_relaxed) + 1;
    fprintf(stderr, CODEPTR_FMT(": rtpp_refcnt(%p, %u).traceen()\n", mlp, pub, oldcnt));
}

static int
rtpp_refcnt_peek(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    PUB2PVT(pub, pvt);
    return atomic_load_explicit(&pvt->cnt, memory_order_relaxed) + 1;
}
#endif
