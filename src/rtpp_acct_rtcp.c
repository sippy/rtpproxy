/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_acct_rtcp.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"

struct rtpp_acct_rtcp_priv {
    struct rtpp_acct_rtcp pub;
    struct rtpa_stats_jitter _jt;
};

static void rtpp_acct_rtcp_dtor(struct rtpp_acct_rtcp_priv *);

struct rtpp_acct_rtcp *
rtpp_acct_rtcp_ctor(const char *call_id, const struct rtp_packet *pp)
{
    struct rtpp_acct_rtcp_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_acct_rtcp_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    RTPP_OBJ_INCREF(pp);
    pvt->pub.pkt = pp;
    pvt->pub.call_id = strdup(call_id);
    if (pvt->pub.call_id == NULL) {
        goto e1;
    }
    pvt->pub.jt = &pvt->_jt;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_acct_rtcp_dtor,
      pvt);
    return ((&pvt->pub));

e1:
    RTPP_OBJ_DECREF(pvt->pub.pkt);
    RTPP_OBJ_DECREF(&(pvt->pub));
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_acct_rtcp_dtor(struct rtpp_acct_rtcp_priv *pvt)
{

    /*rtpp_acct_rtcp_fin(&(pvt->pub));*/
    free((void *)pvt->pub.call_id);
    RTPP_OBJ_DECREF(pvt->pub.pkt);
    free(pvt);
}
