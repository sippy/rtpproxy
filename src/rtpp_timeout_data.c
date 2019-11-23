/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"
#include "rtpp_timeout_data.h"

struct rtpp_timeout_data_priv {
   struct rtpp_timeout_data pub;
};

static void
rtpp_timeout_data_dtor(struct rtpp_timeout_data_priv *pvt)
{

    free((void *)pvt->pub.notify_tag);
    free(pvt);
}

struct rtpp_timeout_data *
rtpp_timeout_data_ctor(struct rtpp_tnotify_target *ttp, const char *tag)
{
    struct rtpp_timeout_data_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_timeout_data_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.notify_tag = strdup(tag);
    if (pvt->pub.notify_tag == NULL) {
        goto e1;
    }
    pvt->pub.notify_target = ttp;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_timeout_data_dtor,
      pvt);
    return ((&pvt->pub));

e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
    free(pvt);
e0:
    return (NULL);
}
