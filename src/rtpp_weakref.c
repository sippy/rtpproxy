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

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_weakref_fin.h"
#include "rtpp_mallocs.h"

DEFINE_CB_STRUCT(rtpp_weakref);

struct rtpp_weakref_priv {
    struct rtpp_weakref pub;
    rtpp_weakref_cb_s on_first;
    rtpp_weakref_cb_s on_last;
    pthread_mutex_t on_lock;
};

static void rtpp_weakref_dtor(struct rtpp_weakref_priv *);
static int rtpp_weakref_reg(struct rtpp_weakref *, struct rtpp_refcnt *, uint64_t);
static void *rtpp_wref_get_by_idx(struct rtpp_weakref *, uint64_t);
static struct rtpp_refcnt *rtpp_weakref_unreg(struct rtpp_weakref *, uint64_t);
static struct rtpp_refcnt *rtpp_weakref_move(struct rtpp_weakref *, uint64_t,
  struct rtpp_weakref *);
static void rtpp_wref_foreach(struct rtpp_weakref *, rtpp_weakref_foreach_t,
  void *);
static int rtpp_wref_get_length(struct rtpp_weakref *);
static int rtpp_wref_purge(struct rtpp_weakref *);
static rtpp_weakref_cb_t rtpp_wref_set_on_first(struct rtpp_weakref *, rtpp_weakref_cb_t,
  void *);
static rtpp_weakref_cb_t rtpp_wref_set_on_last(struct rtpp_weakref *, rtpp_weakref_cb_t,
  void *);

DEFINE_SMETHODS(rtpp_weakref,
    .reg = &rtpp_weakref_reg,
    .get_by_idx = &rtpp_wref_get_by_idx,
    .unreg = &rtpp_weakref_unreg,
    .move = &rtpp_weakref_move,
    .foreach = &rtpp_wref_foreach,
    .get_length = &rtpp_wref_get_length,
    .purge = &rtpp_wref_purge,
    .set_on_first = &rtpp_wref_set_on_first,
    .set_on_last = &rtpp_wref_set_on_last,
);

struct rtpp_weakref *
rtpp_weakref_ctor(void)
{
    struct rtpp_weakref_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_weakref_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->pub.ht = rtpp_hash_table_ctor(rtpp_ht_key_u64_t, RTPP_HT_NODUPS |
      RTPP_HT_DUP_ABRT);
    if (pvt->pub.ht == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->on_lock, NULL) != 0) {
        goto e1;
    }
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_weakref_dtor);
    return (&pvt->pub);
e1:
    RTPP_OBJ_DECREF(pvt->pub.ht);
e0:
    RTPP_OBJ_DECREF(&(pvt->pub));
    return (NULL);
}

static int
rtpp_weakref_reg(struct rtpp_weakref *pub, struct rtpp_refcnt *sp,
  uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_ht_opstats hos, *hosp;
    int rval;

    PUB2PVT(pub, pvt);

    if (pvt->on_first.func != NULL) {
        pthread_mutex_lock(&pvt->on_lock);
        hos.first = 0;
        hosp = &hos;
    } else {
        hosp = NULL;
    }

    rval = 0;
    if (CALL_SMETHOD(pvt->pub.ht, append_refcnt, &suid, sp, hosp) == NULL) {
        rval = -1;
    }
    if (pvt->on_first.func != NULL) {
        if (rval == 0 && hosp->first)
            pvt->on_first.func(pvt->on_first.arg);
        pthread_mutex_unlock(&pvt->on_lock);
    }
    return (rval);
}

static struct rtpp_refcnt *
rtpp_weakref_unreg(struct rtpp_weakref *pub, uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_refcnt *sp;
    struct rtpp_ht_opstats hos, *hosp;

    PUB2PVT(pub, pvt);

    if (pvt->on_last.func != NULL) {
        pthread_mutex_lock(&pvt->on_lock);
        hos.last = 0;
        hosp = &hos;
    } else {
        hosp = NULL;
    }

    sp = CALL_SMETHOD(pvt->pub.ht, remove_by_key, &suid, hosp);

    if (pvt->on_last.func != NULL) {
        if (sp != NULL && hosp->last)
            pvt->on_last.func(pvt->on_last.arg);
        pthread_mutex_unlock(&pvt->on_lock);
    }

    return (sp);
}

static struct rtpp_refcnt *
rtpp_weakref_move(struct rtpp_weakref *pub, uint64_t suid,
  struct rtpp_weakref *other)
{
    struct rtpp_weakref_priv *pvt, *pvt_other;

    struct rtpp_refcnt *sp;
    struct rtpp_ht_opstats hos = {}, *hosp = NULL;

    PUB2PVT(pub, pvt);
    PUB2PVT(other, pvt_other);

    if (pvt->on_last.func != NULL) {
        pthread_mutex_lock(&pvt->on_lock);
        hosp = &hos;
    }
    if (pvt_other->on_first.func != NULL) {
        pthread_mutex_lock(&pvt_other->on_lock);
        hosp = &hos;
    }

    sp = CALL_SMETHOD(pvt->pub.ht, transfer, &suid, pvt_other->pub.ht, hosp);

    if (pvt->on_last.func != NULL) {
        if (sp != NULL && hosp->last)
            pvt->on_last.func(pvt->on_last.arg);
        pthread_mutex_unlock(&pvt->on_lock);
    }
    if (pvt_other->on_first.func != NULL) {
        if (sp != NULL && hosp->first)
            pvt_other->on_first.func(pvt_other->on_first.arg);
        pthread_mutex_unlock(&pvt_other->on_lock);
    }

    return (sp);
}

static void
rtpp_weakref_dtor(struct rtpp_weakref_priv *pvt)
{

    rtpp_weakref_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->on_lock);
    RTPP_OBJ_DECREF(pvt->pub.ht);
}

static void *
rtpp_wref_get_by_idx(struct rtpp_weakref *pub, uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_refcnt *rco;

    PUB2PVT(pub, pvt);

    rco = CALL_SMETHOD(pvt->pub.ht, find, &suid);
    if (rco == NULL) {
        return (NULL);
    }
    return (CALL_SMETHOD(rco, getdata));
}

static void
rtpp_wref_foreach(struct rtpp_weakref *pub, rtpp_weakref_foreach_t foreach_f,
  void *foreach_d)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_ht_opstats hos, *hosp;

    PUB2PVT(pub, pvt);

    if (pvt->on_last.func != NULL) {
        pthread_mutex_lock(&pvt->on_lock);
        hos.last = 0;
        hosp = &hos;
    } else {
        hosp = NULL;
    }

    CALL_SMETHOD(pvt->pub.ht, foreach, foreach_f, foreach_d, hosp);

    if (pvt->on_last.func != NULL) {
        if (hosp->last)
            pvt->on_last.func(pvt->on_last.arg);
        pthread_mutex_unlock(&pvt->on_lock);
    }
}

static int
rtpp_wref_get_length(struct rtpp_weakref *pub)
{
    struct rtpp_weakref_priv *pvt;

    PUB2PVT(pub, pvt);
    return (CALL_SMETHOD(pvt->pub.ht, get_length));
}

static int
rtpp_wref_purge(struct rtpp_weakref *pub)
{
    struct rtpp_weakref_priv *pvt;
    int npurged;

    PUB2PVT(pub, pvt);

    if (pvt->on_last.func != NULL) {
        pthread_mutex_lock(&pvt->on_lock);
    }

    npurged = CALL_SMETHOD(pvt->pub.ht, purge);

    if (pvt->on_last.func != NULL) {
        if (npurged > 0)
            pvt->on_last.func(pvt->on_last.arg);
        pthread_mutex_unlock(&pvt->on_lock);
    }
    return (npurged);
}

static rtpp_weakref_cb_t
rtpp_wref_set_on_first(struct rtpp_weakref *pub, rtpp_weakref_cb_t cb_func,
  void *cb_func_arg)
{
    struct rtpp_weakref_priv *pvt;
    rtpp_weakref_cb_t prev;

    PUB2PVT(pub, pvt);
    prev = pvt->on_first.func;
    pvt->on_first.func = cb_func;
    pvt->on_first.arg = cb_func_arg;
    return (prev);
}

static rtpp_weakref_cb_t
rtpp_wref_set_on_last(struct rtpp_weakref *pub, rtpp_weakref_cb_t cb_func,
  void *cb_func_arg)
{
    struct rtpp_weakref_priv *pvt;
    rtpp_weakref_cb_t prev;

    PUB2PVT(pub, pvt);
    prev = pvt->on_last.func;
    pvt->on_last.func = cb_func;
    pvt->on_last.arg = cb_func_arg;
    return (prev);
}
