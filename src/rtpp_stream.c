/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-20015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdlib.h>
#include <stdint.h>

#include "rtpp_types.h"
#include "rtp_resizer.h"
#include "rtpp_refcnt.h"
#include "rtpp_stream.h"
#include "rtpp_util.h"
#include "rtpp_weakref.h"

struct rtpp_stream_priv
{
    struct rtpp_stream_obj pub;
    struct rtpp_weakref_obj *servers_wrt;
    struct rtpp_stats_obj *rtpp_stats;
    void *rco[0];
};

#define PUB2PVT(pubp) \
  ((struct rtpp_stream_priv *)((char *)(pubp) - offsetof(struct rtpp_stream_priv, pub)))

static void rtpp_stream_dtor(struct rtpp_stream_priv *);

struct rtpp_stream_obj *
rtpp_stream_ctor(struct rtpp_weakref_obj *servers_wrt, struct rtpp_stats_obj *rtpp_stats)
{
    struct rtpp_stream_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_stream_priv) +
      rtpp_refcnt_osize());
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->pub.rcnt = rtpp_refcnt_ctor_pa(&pvt->rco[0], pvt,
      (rtpp_refcnt_dtor_t)&rtpp_stream_dtor);
    if (pvt->pub.rcnt == NULL) {
        free(pvt);
        return (NULL);
    }
    pvt->servers_wrt = servers_wrt;
    pvt->rtpp_stats = rtpp_stats;
    return (&pvt->pub);
}

static void
rtpp_stream_dtor(struct rtpp_stream_priv *pvt)
{
    struct rtpp_stream_obj *pub;

    pub = &(pvt->pub);
    if (pub->addr != NULL)
        free(pub->addr);
    if (pub->prev_addr != NULL)
        free(pub->prev_addr);
    if (pub->codecs != NULL)
        free(pub->codecs);
    if (pub->rtps != RTPP_WEAKID_NONE)
        CALL_METHOD(pvt->servers_wrt, unreg, pub->rtps);
    if (pub->resizer != NULL)
        rtp_resizer_free(pvt->rtpp_stats, pub->resizer);

    free(pvt);
}
