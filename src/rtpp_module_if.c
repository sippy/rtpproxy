/*
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdlib.h>

#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_module_if.h"
#include "rtpp_module_if_fin.h"
#include "rtpp_refcnt.h"

struct rtpp_module_if_priv {
    struct rtpp_module_if pub;
};

static void rtpp_mif_dtor(struct rtpp_module_if_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_module_if_priv *)((char *)(pubp) - offsetof(struct rtpp_module_if_priv, pub)))

struct rtpp_module_if *
rtpp_module_if_ctor(const char *mpath)
{
    struct rtpp_refcnt *rcnt;
    struct rtpp_module_if_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_module_if_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;
    CALL_METHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_mif_dtor,
      pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_mif_dtor(struct rtpp_module_if_priv *pvt)
{

    rtpp_module_if_fin(&(pvt->pub));
    free(pvt);
}
