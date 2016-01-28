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

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "rtpa_stats.h"
#include "rtpp_types.h"
#include "rtpp_analyzer.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_pcount.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_acct.h"
#include "rtpp_acct_fin.h"

struct rtpp_acct_priv {
    struct rtpps_pcount _pcnts_rtp;
    struct rtpps_pcount _pcnts_rtcp;
    struct rtpp_pcnts_strm _pso_rtp;
    struct rtpp_pcnts_strm _psa_rtp;
    struct rtpp_pcnts_strm _pso_rtcp;
    struct rtpp_pcnts_strm _psa_rtcp;
    struct rtpa_stats _rasto;
    struct rtpa_stats _rasta;
    struct rtpa_stats_jitter _jrasto;
    struct rtpa_stats_jitter _jrasta;
    struct rtpp_acct pub;
};

static void rtpp_acct_dtor(struct rtpp_acct_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_acct_priv *)((char *)(pubp) - offsetof(struct rtpp_acct_priv, pub)))

struct rtpp_acct *
rtpp_acct_ctor(uint64_t seuid)
{
    struct rtpp_acct_priv *pvt;
    struct rtpp_refcnt *rcnt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_acct_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.seuid = seuid;
    pvt->pub.rcnt = rcnt;
    pvt->pub.pcnts_rtp = &pvt->_pcnts_rtp;
    pvt->pub.pcnts_rtcp = &pvt->_pcnts_rtcp;
    pvt->pub.pso_rtp = &pvt->_pso_rtp;
    pvt->pub.psa_rtp = &pvt->_psa_rtp;
    pvt->pub.pso_rtcp = &pvt->_pso_rtcp;
    pvt->pub.psa_rtcp = &pvt->_psa_rtcp;
    pvt->pub.rasto = &pvt->_rasto;
    pvt->pub.rasta = &pvt->_rasta;
    pvt->pub.jrasto = &pvt->_jrasto;
    pvt->pub.jrasta = &pvt->_jrasta;
    CALL_METHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_acct_dtor,
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
    free(pvt);
}

const unsigned int
rtpp_acct_osize(void)
{

    return (sizeof(struct rtpp_acct_priv));
}
