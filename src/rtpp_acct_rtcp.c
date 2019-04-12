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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_acct_rtcp.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"

struct rtpp_acct_rtcp_priv {
    struct rtpa_stats_jitter _jt;
    struct rtpp_acct_rtcp pub;
};

static void rtpp_acct_rtcp_dtor(struct rtpp_acct_rtcp_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_acct_rtcp_priv *)((char *)(pubp) - offsetof(struct rtpp_acct_rtcp_priv, pub)))

struct rtpp_acct_rtcp *
rtpp_acct_rtcp_ctor(const char *call_id, const struct rtp_packet *pp)
{
    struct rtpp_acct_rtcp_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_acct_rtcp_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.pkt = rtp_packet_alloc();
    if (pvt->pub.pkt == NULL) {
        goto e1;
    }
    rtp_packet_dup(pvt->pub.pkt, pp, 0);
    pvt->pub.call_id = strdup(call_id);
    if (pvt->pub.call_id == NULL) {
        goto e2;
    }
    pvt->pub.jt = &pvt->_jt;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_acct_rtcp_dtor,
      pvt);
    return ((&pvt->pub));

e2:
    rtp_packet_free(pvt->pub.pkt);
e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_acct_rtcp_dtor(struct rtpp_acct_rtcp_priv *pvt)
{

    /*rtpp_acct_rtcp_fin(&(pvt->pub));*/
    free(pvt->pub.call_id);
    rtp_packet_free(pvt->pub.pkt);
    free(pvt);
}

const unsigned int
rtpp_acct_rtcp_osize(void)
{

    return (sizeof(struct rtpp_acct_rtcp_priv));
}
