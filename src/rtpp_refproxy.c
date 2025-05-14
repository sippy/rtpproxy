/*
 * Copyright (c) 2024 Sippy Software, Inc., http://www.sippysoft.com
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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_refproxy.h"
#include "rtpp_refproxy_fin.h"

struct rtpp_refproxy_priv {
    struct rtpp_refproxy pub;
    int alen;
    int ulen;
    struct rtpp_refcnt *rcnts[0];
};

static void rtpp_refproxy_dtor(struct rtpp_refproxy_priv *);
static void rtpp_refproxy_add(struct rtpp_refproxy *, struct rtpp_refcnt *);

DEFINE_SMETHODS(rtpp_refproxy,
    .add = &rtpp_refproxy_add,
);

struct rtpp_refproxy *
rtpp_refproxy_ctor(int nrefs)
{
    struct rtpp_refproxy_priv *pvt;
    size_t asize = sizeof(struct rtpp_refproxy_priv);

    asize += nrefs * sizeof(struct rtpp_refcnt *);
    pvt = rtpp_rzmalloc(asize, PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->alen = nrefs;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_refproxy_dtor);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_refproxy_dtor(struct rtpp_refproxy_priv *pvt)
{

    rtpp_refproxy_fin(&(pvt->pub));
    for (int i = 0; i < pvt->ulen; i++) {
        RC_DECREF(pvt->rcnts[i]);
    }
}

static void
rtpp_refproxy_add(struct rtpp_refproxy *self, struct rtpp_refcnt *rcnt)
{
    struct rtpp_refproxy_priv *pvt;

    PUB2PVT(self, pvt);
    assert(pvt->alen > pvt->ulen);
    RC_INCREF(rcnt);
    pvt->rcnts[pvt->ulen] = rcnt;
    pvt->ulen += 1;
}
