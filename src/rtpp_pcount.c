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
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_pcount.h"
#include "rtpp_pcount_fin.h"

struct rtpp_pcount_priv {
    struct rtpp_pcount pub;
    struct rtpps_pcount cnt;
    pthread_mutex_t lock;
};

static void rtpp_pcount_dtor(struct rtpp_pcount_priv *);
static void rtpp_pcount_reg_reld(struct rtpp_pcount *);
static void rtpp_pcount_reg_drop(struct rtpp_pcount *);
static void rtpp_pcount_reg_ignr(struct rtpp_pcount *);
static void rtpp_pcount_get_stats(struct rtpp_pcount *, struct rtpps_pcount *);

#define PUB2PVT(pubp) \
  ((struct rtpp_pcount_priv *)((char *)(pubp) - offsetof(struct rtpp_pcount_priv, pub)))

struct rtpp_pcount *
rtpp_pcount_ctor(void)
{
    struct rtpp_pcount_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pcount_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->pub.reg_reld = &rtpp_pcount_reg_reld;
    pvt->pub.reg_drop = &rtpp_pcount_reg_drop;
    pvt->pub.reg_ignr = &rtpp_pcount_reg_ignr;
    pvt->pub.get_stats = &rtpp_pcount_get_stats;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pcount_dtor,
      pvt);
    return ((&pvt->pub));

e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_pcount_dtor(struct rtpp_pcount_priv *pvt)
{

    rtpp_pcount_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static void
rtpp_pcount_reg_reld(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    pvt->cnt.nrelayed++;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_pcount_reg_drop(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    pvt->cnt.ndropped++;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_pcount_reg_ignr(struct rtpp_pcount *self)
{
    struct rtpp_pcount_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    pvt->cnt.nignored++;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_pcount_get_stats(struct rtpp_pcount *self, struct rtpps_pcount *ocnt)
{
    struct rtpp_pcount_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    memcpy(ocnt, &pvt->cnt, sizeof(struct rtpps_pcount));
    pthread_mutex_unlock(&pvt->lock);
}
