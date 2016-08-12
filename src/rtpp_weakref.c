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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_mallocs.h"

struct rtpp_weakref_priv {
    struct rtpp_weakref_obj pub;
    struct rtpp_hash_table *ht;
};

#define PUB2PVT(pubp)      ((struct rtpp_weakref_priv *)((char *)(pubp) - offsetof(struct rtpp_weakref_priv, pub)))

static void rtpp_weakref_dtor(struct rtpp_weakref_obj *);
static int rtpp_weakref_reg(struct rtpp_weakref_obj *, struct rtpp_refcnt *, uint64_t);
static void *rtpp_wref_get_by_idx(struct rtpp_weakref_obj *, uint64_t);
static struct rtpp_refcnt *rtpp_weakref_unreg(struct rtpp_weakref_obj *, uint64_t);
static void rtpp_wref_foreach(struct rtpp_weakref_obj *, rtpp_weakref_foreach_t,
  void *);
static int rtpp_wref_get_length(struct rtpp_weakref_obj *);
static int rtpp_wref_purge(struct rtpp_weakref_obj *);

struct rtpp_weakref_obj *
rtpp_weakref_ctor(void)
{
    struct rtpp_weakref_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_weakref_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->ht = rtpp_hash_table_ctor(rtpp_ht_key_u64_t, RTPP_HT_NODUPS |
      RTPP_HT_DUP_ABRT);
    if (pvt->ht == NULL) {
        goto e0;
    }
    pvt->pub.dtor = &rtpp_weakref_dtor;
    pvt->pub.reg = &rtpp_weakref_reg;
    pvt->pub.get_by_idx = &rtpp_wref_get_by_idx;
    pvt->pub.unreg = &rtpp_weakref_unreg;
    pvt->pub.foreach = &rtpp_wref_foreach;
    pvt->pub.get_length = &rtpp_wref_get_length;
    pvt->pub.purge = &rtpp_wref_purge;
    return (&pvt->pub);

e0:
    free(pvt);
    return (NULL);
}

static int
rtpp_weakref_reg(struct rtpp_weakref_obj *pub, struct rtpp_refcnt *sp,
  uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;

    pvt = PUB2PVT(pub);

    if (CALL_METHOD(pvt->ht, append_refcnt, &suid, sp) == NULL) {
        return (-1);
    }
    return (0);
}

static struct rtpp_refcnt *
rtpp_weakref_unreg(struct rtpp_weakref_obj *pub, uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_refcnt *sp;

    pvt = PUB2PVT(pub);

    sp = CALL_METHOD(pvt->ht, remove_by_key, &suid);
    return (sp);
}

static void
rtpp_weakref_dtor(struct rtpp_weakref_obj *pub)
{
    struct rtpp_weakref_priv *pvt;

    pvt = PUB2PVT(pub);

    CALL_METHOD(pvt->ht, dtor);
    free(pvt);
}

static void *
rtpp_wref_get_by_idx(struct rtpp_weakref_obj *pub, uint64_t suid)
{
    struct rtpp_weakref_priv *pvt;
    struct rtpp_refcnt *rco;

    pvt = PUB2PVT(pub);

    rco = CALL_METHOD(pvt->ht, find, &suid);
    if (rco == NULL) {
        return (NULL);
    }
    return (CALL_SMETHOD(rco, getdata));
}

static void
rtpp_wref_foreach(struct rtpp_weakref_obj *pub, rtpp_weakref_foreach_t foreach_f,
  void *foreach_d)
{
    struct rtpp_weakref_priv *pvt;

    pvt = PUB2PVT(pub);
    CALL_METHOD(pvt->ht, foreach, foreach_f, foreach_d);
}

static int
rtpp_wref_get_length(struct rtpp_weakref_obj *pub)
{
    struct rtpp_weakref_priv *pvt;

    pvt = PUB2PVT(pub);
    return (CALL_METHOD(pvt->ht, get_length));
}

static int
rtpp_wref_purge(struct rtpp_weakref_obj *pub)
{
    struct rtpp_weakref_priv *pvt;

    pvt = PUB2PVT(pub);
    return (CALL_METHOD(pvt->ht, purge));
}
