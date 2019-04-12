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

#include <stdint.h>
#include <stdlib.h>

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_types.h"
#include "rtpp_time.h"
#include "rtpp_pcnts_strm.h"
#include "rtpp_pcount.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_netaddr.h"

struct rtpp_acct_face_s {
    struct rtpp_pcnts_strm ps;
};

struct rtpp_acct_pipe_s {
    struct rtpp_acct_face_s o;
    struct rtpp_acct_face_s a;
    struct rtpps_pcount pcnts;
};

struct rtpp_acct_priv {
    struct rtpp_acct_pipe_s _rtp;
    struct rtpp_acct_pipe_s _rtcp;
    struct rtpa_stats _rasto;
    struct rtpa_stats _rasta;
    struct rtpa_stats_jitter _jrasto;
    struct rtpa_stats_jitter _jrasta;
    struct rtpp_timestamp _init_ts;
    struct rtpp_timestamp _destroy_ts;
    struct rtpp_acct pub;
};

static void rtpp_acct_dtor(struct rtpp_acct_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_acct_priv *)((char *)(pubp) - offsetof(struct rtpp_acct_priv, pub)))

struct rtpp_acct *
rtpp_acct_ctor(uint64_t seuid)
{
    struct rtpp_acct_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_acct_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.seuid = seuid;
    pvt->pub.rtp.pcnts = &pvt->_rtp.pcnts;
    pvt->pub.rtcp.pcnts = &pvt->_rtcp.pcnts;
    pvt->pub.rtp.o.ps = &pvt->_rtp.o.ps;
    pvt->pub.rtp.a.ps = &pvt->_rtp.a.ps;
    pvt->pub.rtcp.o.ps = &pvt->_rtcp.o.ps;
    pvt->pub.rtcp.a.ps = &pvt->_rtcp.a.ps;
    pvt->pub.rasto = &pvt->_rasto;
    pvt->pub.rasta = &pvt->_rasta;
    pvt->pub.jrasto = &pvt->_jrasto;
    pvt->pub.jrasta = &pvt->_jrasta;
    pvt->pub.init_ts = &pvt->_init_ts;
    pvt->pub.destroy_ts = &pvt->_destroy_ts;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_acct_dtor,
      pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_acct_dtor(struct rtpp_acct_priv *pvt)
{

    /*rtpp_acct_fin(&(pvt->pub));*/
    if (pvt->pub.call_id != NULL)
        free(pvt->pub.call_id);
    if (pvt->pub.from_tag != NULL)
        free(pvt->pub.from_tag);
    if (pvt->pub.rtp.a.rem_addr != NULL)
        CALL_SMETHOD(pvt->pub.rtp.a.rem_addr->rcnt, decref);
    if (pvt->pub.rtp.o.rem_addr != NULL)
        CALL_SMETHOD(pvt->pub.rtp.o.rem_addr->rcnt, decref);
    if (pvt->pub.rtcp.a.rem_addr != NULL)
        CALL_SMETHOD(pvt->pub.rtcp.a.rem_addr->rcnt, decref);
    if (pvt->pub.rtcp.o.rem_addr != NULL)
        CALL_SMETHOD(pvt->pub.rtcp.o.rem_addr->rcnt, decref);
    free(pvt);
}

const unsigned int
rtpp_acct_osize(void)
{

    return (sizeof(struct rtpp_acct_priv));
}
