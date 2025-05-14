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
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_ttl.h"
#include "rtpp_ttl_fin.h"

struct rtpp_ttl_priv {
    struct rtpp_ttl pub;
    int max_ttl;
    int ttl;
    pthread_mutex_t lock;
};

static void rtpp_ttl_dtor(struct rtpp_ttl_priv *);
static void rtpp_ttl_reset(struct rtpp_ttl *);
static void rtpp_ttl_reset_with(struct rtpp_ttl *, int);
static int rtpp_ttl_get_remaining(struct rtpp_ttl *);
static int rtpp_ttl_decr(struct rtpp_ttl *);

DEFINE_SMETHODS(rtpp_ttl,
    .reset = &rtpp_ttl_reset,
    .reset_with = &rtpp_ttl_reset_with,
    .get_remaining = &rtpp_ttl_get_remaining,
    .decr = &rtpp_ttl_decr,
);

struct rtpp_ttl *
rtpp_ttl_ctor(int max_ttl)
{
    struct rtpp_ttl_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_ttl_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->ttl = pvt->max_ttl = max_ttl;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_ttl_dtor);
    return ((&pvt->pub));

e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
rtpp_ttl_dtor(struct rtpp_ttl_priv *pvt)
{

    rtpp_ttl_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->lock);
}

static void
rtpp_ttl_reset(struct rtpp_ttl *self)
{
    struct rtpp_ttl_priv *pvt;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->lock);
    pvt->ttl = pvt->max_ttl;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_ttl_reset_with(struct rtpp_ttl *self, int max_ttl)
{
    struct rtpp_ttl_priv *pvt;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->lock);
    pvt->ttl = max_ttl;
    pvt->max_ttl = max_ttl;
    pthread_mutex_unlock(&pvt->lock);
}

static int
rtpp_ttl_get_remaining(struct rtpp_ttl *self)
{
    struct rtpp_ttl_priv *pvt;
    int rval;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->lock);
    rval = pvt->ttl;
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static int
rtpp_ttl_decr(struct rtpp_ttl *self)
{
    struct rtpp_ttl_priv *pvt;
    int rval;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->lock);
    rval = pvt->ttl;
    if (pvt->ttl > 0)
        pvt->ttl--;
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}
