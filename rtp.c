/*
 * Copyright (c) 2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id: rtp.c,v 1.6 2007/11/19 22:44:31 sobomax Exp $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "rtp.h"
#include "rtpp_util.h"

/* Linked list of free packets */
static struct rtp_packet *rtp_packet_pool = NULL;

size_t 
rtp_samples2bytes(int codec_id, int nsamples)
{

    switch (codec_id) {
        case RTP_PCMU:
        case RTP_PCMA:
            return nsamples;
        case RTP_G729:
            return nsamples / 8;
        case RTP_GSM:
            return (nsamples / 160) * 33;
        case RTP_G723:
            return (nsamples / 240) * 24;
        default:
            return RTP_NSAMPLES_UNKNOWN;
    }
}

int 
rtp_bytes2samples(int codec_id, size_t nbytes)
{

    switch (codec_id) {
        case RTP_PCMU:
        case RTP_PCMA:
            return nbytes;
        case RTP_G729:
            return nbytes * 8;
        case RTP_GSM:
            return 160 * (nbytes / 33);
        case RTP_G723:
            if (nbytes % 24 == 0) 
                return 240 * (nbytes / 24);
#if defined(NOTYET)
            else if (nbytes % 20 == 0)
                return 240 * (nbytes / 20);
#endif
        default:
            return RTP_NSAMPLES_UNKNOWN;
    }
}

void 
rtp_packet_parse(struct rtp_packet *pkt)
{
    int padding_size = 0;

    pkt->data_size = 0;
    pkt->data_offset = 0;
    pkt->nsamples = RTP_NSAMPLES_UNKNOWN;

    if (pkt->header.version != 2)
        return;

    pkt->data_offset = RTP_HDR_LEN(&pkt->header);

    if (pkt->header.p)
        padding_size = ((unsigned char *) pkt)[pkt->size - 1];

    pkt->data_size = pkt->size - pkt->data_offset - padding_size;
    pkt->nsamples = rtp_bytes2samples(pkt->header.pt, pkt->data_size);
    pkt->ts = ntohl(pkt->header.ts);
    pkt->seq = ntohs(pkt->header.seq);
}

struct rtp_packet *
rtp_packet_alloc()
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_pool;
    if (pkt != NULL)
        rtp_packet_pool = pkt->next;
    else
        pkt = malloc(sizeof(*pkt));
    return pkt;
}

void
rtp_packet_free(struct rtp_packet *pkt)
{
    pkt->next = rtp_packet_pool;
    pkt->prev = NULL;
    rtp_packet_pool = pkt;
}

struct rtp_packet *
rtp_recv(int fd)
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_alloc();

    if (pkt == NULL)
        return NULL;

    pkt->rlen = sizeof(pkt->raddr);
    pkt->size = recvfrom(fd, pkt->buf, sizeof(pkt->buf), 0, 
      sstosa(&pkt->raddr), &pkt->rlen);

    if (pkt->size == -1) {
	rtp_packet_free(pkt);
	return NULL;
    }

    return pkt;
}

void 
rtp_packet_set_seq(struct rtp_packet *p, uint16_t seq)
{

    p->seq = seq;
    p->header.seq = htons(seq);
}

void 
rtp_packet_set_ts(struct rtp_packet *p, uint32_t ts)
{

    p->ts = ts;
    p->header.ts = htonl(ts);
}
