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

#ifndef HAVE_GCC_ATOMICS
#include <pthread.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_refcnt_fin.h"

#if RTPP_DEBUG_refcnt
#include <stdio.h>
#ifdef RTPP_DEBUG
#include "rtpp_stacktrace.h"
#endif
#endif

/*
 * Somewhat arbitrary cap on the maximum value of the references. Just here
 * to catch any runaway situations, i.e. bugs in the code.
 */
#define RC_ABS_MAX 2000000

#define RC_FLAG_PA    (1 << 0)
#define RC_FLAG_TRACE (1 << 1)

struct rtpp_refcnt_priv
{
    struct rtpp_refcnt pub;
    volatile int32_t cnt;
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_t cnt_lock;
#endif
    rtpp_refcnt_dtor_t dtor_f;
    void *data;
    rtpp_refcnt_dtor_t pre_dtor_f;
    void *pd_data;
    int flags;
};

static void rtpp_refcnt_attach(struct rtpp_refcnt *, rtpp_refcnt_dtor_t,
  void *);
static void rtpp_refcnt_incref(struct rtpp_refcnt *);
static void rtpp_refcnt_decref(struct rtpp_refcnt *);
static void *rtpp_refcnt_getdata(struct rtpp_refcnt *);
static void rtpp_refcnt_reg_pd(struct rtpp_refcnt *, rtpp_refcnt_dtor_t,
  void *);
#if RTPP_DEBUG_refcnt
static void rtpp_refcnt_traceen(struct rtpp_refcnt *);
#endif

const struct rtpp_refcnt_smethods rtpp_refcnt_smethods = {
    .incref = &rtpp_refcnt_incref,
    .decref = &rtpp_refcnt_decref,
    .getdata = &rtpp_refcnt_getdata,
    .reg_pd = &rtpp_refcnt_reg_pd,
#if RTPP_DEBUG_refcnt
    .traceen = rtpp_refcnt_traceen,
#endif
    .attach = &rtpp_refcnt_attach
};

struct rtpp_refcnt *
rtpp_refcnt_ctor(void *data, rtpp_refcnt_dtor_t dtor_f)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_refcnt_priv));
    if (pvt == NULL) {
        return (NULL);
    }
#ifndef HAVE_GCC_ATOMICS
    if (pthread_mutex_init(&pvt->cnt_lock, NULL) != 0) {
        free(pvt);
        return (NULL);
    }
#endif
    pvt->data = data;
    if (dtor_f != NULL) {
        pvt->dtor_f = dtor_f;
    } else {
        pvt->dtor_f = free;
    }
    pvt->pub.smethods = &rtpp_refcnt_smethods;
    pvt->cnt = 1;
    return (&pvt->pub);
}

const unsigned int
rtpp_refcnt_osize(void)
{

    return (sizeof(struct rtpp_refcnt_priv));
}

struct rtpp_refcnt *
rtpp_refcnt_ctor_pa(void *pap)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pap;
#ifndef HAVE_GCC_ATOMICS
    if (pthread_mutex_init(&pvt->cnt_lock, NULL) != 0) {
        return (NULL);
    }
#endif
    pvt->pub.smethods = &rtpp_refcnt_smethods;
    pvt->cnt = 1;
    pvt->flags |= RC_FLAG_PA;
    return (&pvt->pub);
}

static void
rtpp_refcnt_attach(struct rtpp_refcnt *pub, rtpp_refcnt_dtor_t dtor_f,
  void *data)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    pvt->data = data;
    pvt->dtor_f = dtor_f;
}

static void
rtpp_refcnt_incref(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_lock(&pvt->cnt_lock);
#endif
#if RTPP_DEBUG_refcnt
    if (pvt->flags & RC_FLAG_TRACE) {
        char *dbuf;
        asprintf(&dbuf, "rtpp_refcnt(%p, %u).incref()", pub, pvt->cnt);
        if (dbuf != NULL) {
#ifdef RTPP_DEBUG
            rtpp_stacktrace_print(dbuf);
#else
            fprintf(stderr, "%s\n", dbuf);
#endif
            free(dbuf);
        }
    }
#endif
    RTPP_DBG_ASSERT(pvt->cnt > 0 && pvt->cnt < RC_ABS_MAX);
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_unlock(&pvt->cnt_lock);
    pvt->cnt += 1;
#else
    __sync_fetch_and_add(&pvt->cnt, 1);
#endif
}

static void
rtpp_refcnt_decref(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;
    int oldcnt;

    pvt = (struct rtpp_refcnt_priv *)pub;
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_lock(&pvt->cnt_lock);
    oldcnt = pvt->cnt;
    pvt->cnt -= 1;
#else
    oldcnt = __sync_fetch_and_add(&pvt->cnt, -1);
#endif
#if RTPP_DEBUG_refcnt
    if (pvt->flags & RC_FLAG_TRACE) {
        char *dbuf;
        asprintf(&dbuf, "rtpp_refcnt(%p, %u).decref()", pub, oldcnt);
        if (dbuf != NULL) {
#ifdef RTPP_DEBUG
            rtpp_stacktrace_print(dbuf);
#else
            fprintf(stderr, "%s\n", dbuf);
#endif
            free(dbuf);
        }
    }
#endif
    if (oldcnt == 1) {
        if ((pvt->flags & RC_FLAG_PA) == 0) {
            if (pvt->pre_dtor_f != NULL) {
                pvt->pre_dtor_f(pvt->pd_data);
            }
            pvt->dtor_f(pvt->data);
            rtpp_refcnt_fin(pub);
#ifndef HAVE_GCC_ATOMICS
            pthread_mutex_unlock(&pvt->cnt_lock);
            pthread_mutex_destroy(&pvt->cnt_lock);
#endif
            free(pvt);
        } else {
#ifndef HAVE_GCC_ATOMICS
            pthread_mutex_unlock(&pvt->cnt_lock);
            pthread_mutex_destroy(&pvt->cnt_lock);
#endif
            rtpp_refcnt_fin(pub);
            if (pvt->pre_dtor_f != NULL) {
                pvt->pre_dtor_f(pvt->pd_data);
            }
            if (pvt->dtor_f != NULL) {
                pvt->dtor_f(pvt->data);
            }
        }

        return;
    }
#ifndef HAVE_GCC_ATOMICS
    RTPP_DBG_ASSERT(pvt->cnt > 0);
    pthread_mutex_unlock(&pvt->cnt_lock);
#endif
}

#if 0
/*
 * Special case destructor, only when we want to abort object without
 * calling any registered callbacks, i.e. when rolling back failed
 * constructor in the complex class.
 */
static void
rtpp_refcnt_abort(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_lock(&pvt->cnt_lock);
#endif
    RTPP_DBG_ASSERT(pvt->cnt == 1);
#ifndef HAVE_GCC_ATOMICS
    pthread_mutex_unlock(&pvt->cnt_lock);
    pthread_mutex_destroy(&pvt->cnt_lock);
#endif
    if ((pvt->flags & RC_FLAG_PA) == 0) {
        free(pvt);
    }
    return;
}
#endif

static void *
rtpp_refcnt_getdata(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    RTPP_DBG_ASSERT(pvt->cnt > 0);
    return (pvt->data);
}

static void
rtpp_refcnt_reg_pd(struct rtpp_refcnt *pub, rtpp_refcnt_dtor_t pre_dtor_f,
  void *pd_data)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    RTPP_DBG_ASSERT(pvt->pre_dtor_f == NULL);
    pvt->pre_dtor_f = pre_dtor_f;
    pvt->pd_data = pd_data;
}

#if RTPP_DEBUG_refcnt
static void
rtpp_refcnt_traceen(struct rtpp_refcnt *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    pvt->flags |= RC_FLAG_TRACE;
}
#endif
