/*
 * Copyright (c) 2007-2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <stddef.h>

#include "rtp.h"
#include "rtp_info.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"

#include "rtpp_wi.h"
#include "rtpp_wi_private.h"

struct rtp_packet_full;

static void rtp_packet_free(struct rtp_packet_full *);

struct rtp_packet_priv {
    struct rtp_info rinfo;
    struct rtpp_wi_pvt wip;
};

struct rtp_packet_full {
    struct rtp_packet pub;
    struct rtp_packet_priv pvt;
};

void
rtp_packet_dup(struct rtp_packet *dpkt, const struct rtp_packet *spkt, int flags)
{
    int csize, offst;
    struct rtp_packet_full *dpkt_full, *spkt_full;

    csize = offsetof(struct rtp_packet, data.buf) + spkt->size;
    if ((flags & RTPP_DUP_HDRONLY) != 0) {
        assert(spkt->parse_result == RTP_PARSER_OK);
        csize -= spkt->parsed->data_size;
    }
    offst = RTP_PKT_COPYOFF(spkt);
    memcpy(((char *)dpkt) + offst, ((char *)spkt) + offst, csize - offst);
    if (spkt->parsed == NULL) {
        return;
    }
    PUB2PVT(dpkt, dpkt_full);
    PUB2PVT(spkt, spkt_full);
    dpkt_full->pvt.rinfo = spkt_full->pvt.rinfo;
    dpkt->parsed = &(dpkt_full->pvt.rinfo);
    if ((flags & RTPP_DUP_HDRONLY) != 0) {
        dpkt->size -= dpkt->parsed->data_size;
        dpkt->parsed->data_size = 0;
        dpkt->parsed->nsamples = 0;
    }
}

struct rtp_packet *
rtp_packet_alloc()
{
    struct rtp_packet_full *pkt;

    pkt = rtpp_rzmalloc(sizeof(*pkt), PVT_RCOFFS(pkt));
    if (pkt == NULL) {
        return (NULL);
    }
    pkt->pub.wi = &(pkt->pvt.wip.pub);
    CALL_SMETHOD(pkt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtp_packet_free,
      pkt);

    return &(pkt->pub);
}

static void
rtp_packet_free(struct rtp_packet_full *pkt)
{

    free(pkt);
}

void 
rtp_packet_set_seq(struct rtp_packet *p, uint16_t seq)
{

    p->parsed->seq = seq;
    p->data.header.seq = htons(seq);
}

void 
rtp_packet_set_ts(struct rtp_packet *p, uint32_t ts)
{

    p->parsed->ts = ts;
    p->data.header.ts = htonl(ts);
}

rtp_parser_err_t
rtp_packet_parse(struct rtp_packet *pkt)
{
    struct rtp_packet_full *pkt_full;
    struct rtp_info *rinfo;

    if (pkt->parse_result != RTP_PARSER_NOTPARSED) {
        return (pkt->parse_result);
    }
    assert(pkt->parsed == NULL);
    pkt_full = (void *)pkt;
    rinfo = &(pkt_full->pvt.rinfo);
    pkt->parse_result = rtp_packet_parse_raw(pkt->data.buf, pkt->size, rinfo);
    if (pkt->parse_result == RTP_PARSER_OK) {
        pkt->parsed = rinfo;
    }
    return (pkt->parse_result);
}
