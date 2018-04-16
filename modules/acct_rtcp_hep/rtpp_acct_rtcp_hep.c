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

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_module.h"
#include "rtpp_cfg_stable.h"

struct rtpp_module_priv {
   int dummy;
};

static struct rtpp_module_priv *rtpp_acct_rtcp_hep_ctor(struct rtpp_cfg_stable *);
static void rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *);
#if 0
static void rtpp_acct_rtcp_hep_do(struct rtpp_module_priv *, struct rtpp_acct *);
#endif

#define API_FUNC(fname, asize) {.func = (fname), .argsize = (asize)}

struct rtpp_minfo rtpp_module = {
    .name = "acct_rtcp_hep",
    .ver = MI_VER_INIT(),
    .ctor = rtpp_acct_rtcp_hep_ctor,
    .dtor = rtpp_acct_rtcp_hep_dtor,
#if 0
    .on_session_end = API_FUNC(rtpp_acct_rtcp_hep_do, rtpp_acct_OSIZE())
#endif
};

static struct rtpp_module_priv *
rtpp_acct_rtcp_hep_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    return (pvt);

#if 0
e1:
    mod_free(pvt);
#endif
e0:
    return (NULL);
}

static void
rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}
