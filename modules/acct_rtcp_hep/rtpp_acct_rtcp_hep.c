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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_module.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_acct_rtcp.h"
#include "rtpp_monotime.h"
#include "rtpp_network.h"
#include "rtpp_time.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_ssrc.h"
#include "rtpa_stats.h"

#include "core_hep.h"
#include "hep_api.h"

#include "_acct_rtcp_hep_config.h"

struct rtpp_module_priv {
   int dummy;
};

static struct rtpp_module_priv *rtpp_acct_rtcp_hep_ctor(struct rtpp_cfg_stable *);
static void rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *);
static void rtpp_acct_rtcp_hep_do(struct rtpp_module_priv *, struct rtpp_acct_rtcp *);

#define API_FUNC(fname, asize) {.func = (fname), .argsize = (asize)}

struct rtpp_minfo rtpp_module = {
    .name = "acct_rtcp_hep",
    .ver = MI_VER_INIT(),
    .ctor = rtpp_acct_rtcp_hep_ctor,
    .dtor = rtpp_acct_rtcp_hep_dtor,
    .on_rtcp_rcvd = API_FUNC(rtpp_acct_rtcp_hep_do, rtpp_acct_rtcp_OSIZE())
};

void
handler(int param)
{
    mod_log(RTPP_LOG_ERR, "rtpp_acct_rtcp_hep: handler(%d)", param);

    return;
}

static struct rtpp_module_priv *
rtpp_acct_rtcp_hep_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    if (init_hepsocket(&ctx) != 0) {
        goto e1;
    }
    return (pvt);

e1:
    mod_free(pvt);
e0:
    return (NULL);
}

static void
rtpp_acct_rtcp_hep_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}

static void
rtpp_acct_rtcp_hep_do(struct rtpp_module_priv *pvt, struct rtpp_acct_rtcp *rarp)
{
    struct rc_info ri;
    char src_ip[256], dst_ip[256];
    struct sockaddr *src_addr, *dst_addr;
    struct timeval rtimeval;

    memset(&ri, '\0', sizeof(ri));

    src_addr = sstosa(&(rarp->pkt->raddr));
    dst_addr = rarp->pkt->laddr;
    addr2char_r(src_addr, src_ip, sizeof(src_ip));
    addr2char_r(dst_addr, dst_ip, sizeof(dst_ip));
    ri.ip_family = AF_INET;
    ri.ip_proto = 17; /* UDP */
    ri.proto_type = 5; /* RTCP */
    ri.src_ip = src_ip;
    ri.dst_ip = dst_ip;
    ri.src_port = getnport(src_addr);
    ri.dst_port = getnport(dst_addr);
    dtime2rtimeval(rarp->pkt->rtime, &rtimeval);
    ri.time_sec = SEC(&rtimeval);
    ri.time_usec = USEC(&rtimeval);

    mod_log(RTPP_LOG_ERR, "rtpp_acct_rtcp_hep_do: send_hepv3 = %d",
      send_hepv3(&ctx, &ri, rarp->pkt->data.buf, rarp->pkt->size, 0));
    
    return;
}
