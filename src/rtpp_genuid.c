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
#include "rtpp_genuid.h"
#include "rtpp_mallocs.h"

struct rtpp_genuid_priv {
    struct rtpp_genuid_obj pub;
    uint64_t lastsuid;
    pthread_mutex_t lastsuid_lock;
};

#define PUB2PVT(pubp)      ((struct rtpp_genuid_priv *)((char *)(pubp) - offsetof(struct rtpp_genuid_priv, pub)))

static void rtpp_genuid_gen(struct rtpp_genuid_obj *, uint64_t *vp);
static void rtpp_genuid_dtor(struct rtpp_genuid_obj *);

struct rtpp_genuid_obj *
rtpp_genuid_ctor(void)
{
    struct rtpp_genuid_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_genuid_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    if (pthread_mutex_init(&pvt->lastsuid_lock, NULL) != 0) {
        goto e0;
    }
    pvt->pub.dtor = &rtpp_genuid_dtor;
    pvt->pub.gen = &rtpp_genuid_gen;
    return (&pvt->pub);

e0:
    free(pvt);
    return (NULL);
}

static void
rtpp_genuid_dtor(struct rtpp_genuid_obj *pub)
{
    struct rtpp_genuid_priv *pvt;

    pvt = PUB2PVT(pub);

    pthread_mutex_destroy(&pvt->lastsuid_lock);
    free(pvt);
}

static void
rtpp_genuid_gen(struct rtpp_genuid_obj *pub, uint64_t *vp)
{
    struct rtpp_genuid_priv *pvt;

    pvt = PUB2PVT(pub);

    pthread_mutex_lock(&pvt->lastsuid_lock);
    *vp = ++(pvt->lastsuid);
    pthread_mutex_unlock(&pvt->lastsuid_lock);
}
