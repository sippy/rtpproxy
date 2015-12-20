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

#include <stdint.h>
#include <stdlib.h>

#include "rtpp_genuid_singlet.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_weakref.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_ttl.h"
#include "rtpp_math.h"

struct rtpp_pipe_priv
{
    struct rtpp_pipe pub;
    struct rtpp_weakref_obj *streams_wrt;
    int session_type;
};

static void rtpp_pipe_dtor(struct rtpp_pipe_priv *);
static int rtpp_pipe_get_ttl(struct rtpp_pipe *);
static void rtpp_pipe_decr_ttl(struct rtpp_pipe *);

struct rtpp_pipe *
rtpp_pipe_ctor(uint64_t seuid, struct rtpp_weakref_obj *streams_wrt,
  struct rtpp_weakref_obj *servers_wrt, struct rtpp_log *log,
  struct rtpp_stats *rtpp_stats, int session_type)
{
    struct rtpp_pipe_priv *pvt;
    struct rtpp_refcnt *rcnt;
    int i;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pipe_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;

    pvt->streams_wrt = streams_wrt;

    rtpp_gen_uid(&pvt->pub.ppuid);
    for (i = 0; i < 2; i++) {
        pvt->pub.stream[i] = rtpp_stream_ctor(log, servers_wrt,
          rtpp_stats, i, session_type, seuid);
        if (pvt->pub.stream[i] == NULL) {
            goto e1;
        }
        if (CALL_METHOD(pvt->streams_wrt, reg, pvt->pub.stream[i]->rcnt,
          pvt->pub.stream[i]->stuid) != 0) {
            goto e1;
        }
    }
    pvt->pub.stream[0]->stuid_sendr = pvt->pub.stream[1]->stuid;
    pvt->pub.stream[1]->stuid_sendr = pvt->pub.stream[0]->stuid;
    pvt->pub.pcount = rtpp_pcount_ctor();
    if (pvt->pub.pcount == NULL) {
        goto e2;
    }
    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->pub.pcount->rcnt, incref);
        pvt->pub.stream[i]->pcount = pvt->pub.pcount;
    }
    pvt->session_type = session_type;
    pvt->pub.rtpp_stats = rtpp_stats;
    pvt->pub.log = log;
    pvt->pub.get_ttl = &rtpp_pipe_get_ttl;
    pvt->pub.decr_ttl = &rtpp_pipe_decr_ttl;
    CALL_METHOD(log->rcnt, incref);
    CALL_METHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pipe_dtor, pvt);
    return (&pvt->pub);

e2:
e1:
    for (i = 0; i < 2; i++) {
        if (pvt->pub.stream[i] != NULL) {
            CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
            CALL_METHOD(pvt->pub.stream[i]->rcnt, decref);
        }
    }
    CALL_METHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_pipe_dtor(struct rtpp_pipe_priv *pvt)
{
    int i;

    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
        CALL_METHOD(pvt->pub.stream[i]->rcnt, decref);
    }
    CALL_METHOD(pvt->pub.pcount->rcnt, decref);
    CALL_METHOD(pvt->pub.log->rcnt, decref);
    free(pvt);
}

static int
rtpp_pipe_get_ttl(struct rtpp_pipe *self)
{
    int ttls[2];

    ttls[0] = CALL_METHOD(self->stream[0]->ttl, get_remaining);
    ttls[1] = CALL_METHOD(self->stream[1]->ttl, get_remaining);
    return (MIN(ttls[0], ttls[1]));
}

static void
rtpp_pipe_decr_ttl(struct rtpp_pipe *self)
{
    CALL_METHOD(self->stream[0]->ttl, decr);
    if (self->stream[1]->ttl == self->stream[0]->ttl)
        return;
    CALL_METHOD(self->stream[1]->ttl, decr);
}
