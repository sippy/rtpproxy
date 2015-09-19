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
#include "rtpp_streamdb.h"
#include "rtpp_util.h"

struct rtpp_streamdb_priv {
    struct rtpp_streamdb_obj pub;
    uint64_t lastsuid;
    pthread_mutex_t lastsuid_lock;
    struct rtpp_hash_table_obj *ht;
};

#define PUB2PVT(pubp)      ((struct rtpp_streamdb_priv *)((char *)(pubp) - offsetof(struct rtpp_streamdb_priv, pub)))

static void rtpp_streamdb_dtor(struct rtpp_streamdb_obj *);
static uint64_t rtpp_streamdb_append(struct rtpp_streamdb_obj *, struct rtpp_refcnt_obj *);
static struct rtpp_refcnt_obj *rtpp_sdb_get_by_idx(struct rtpp_streamdb_obj *, uint64_t);

struct rtpp_streamdb_obj *
rtpp_streamdb_ctor(void)
{
    struct rtpp_streamdb_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_streamdb_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    if (pthread_mutex_init(&pvt->lastsuid_lock, NULL) != 0) {
        goto e0;
    }
    pvt->ht = rtpp_hash_table_ctor(rtpp_ht_key_u64_t, RTPP_HT_NODUPS |
      RTPP_HT_DUP_ABRT);
    if (pvt->ht == NULL) {
        goto e1;
    }
    pvt->pub.dtor = &rtpp_streamdb_dtor;
    pvt->pub.append = &rtpp_streamdb_append;
    pvt->pub.get_by_idx = &rtpp_sdb_get_by_idx;
    return (&pvt->pub);

e1:
    pthread_mutex_destroy(&pvt->lastsuid_lock);
e0:
    free(pvt);
    return (NULL);
}

static uint64_t
rtpp_streamdb_append(struct rtpp_streamdb_obj *pub, struct rtpp_refcnt_obj *sp)
{
    struct rtpp_streamdb_priv *pvt;
    uint64_t suid;

    pvt = PUB2PVT(pub);

    pthread_mutex_lock(&pvt->lastsuid_lock);
    pvt->lastsuid++;
    suid = pvt->lastsuid;
    pthread_mutex_unlock(&pvt->lastsuid_lock);

    CALL_METHOD(pvt->ht, append_refcnt, &suid, sp);
    return (suid);
}

static void
rtpp_streamdb_dtor(struct rtpp_streamdb_obj *pub)
{
    struct rtpp_streamdb_priv *pvt;

    pvt = PUB2PVT(pub);

    CALL_METHOD(pvt->ht, dtor);
    pthread_mutex_destroy(&pvt->lastsuid_lock);
    free(pvt);
}

static struct rtpp_refcnt_obj *
rtpp_sdb_get_by_idx(struct rtpp_streamdb_obj *pub, uint64_t suid)
{
    struct rtpp_streamdb_priv *pvt;
    struct rtpp_refcnt_obj *sp;

    pvt = PUB2PVT(pub);

    sp = CALL_METHOD(pvt->ht, find, &suid);
    return (sp);
}
