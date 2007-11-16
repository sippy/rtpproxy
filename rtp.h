/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id: rtp.h,v 1.6 2007/11/16 08:43:26 sobomax Exp $
 *
 */

#ifndef _RTP_H_
#define _RTP_H_

#include <sys/types.h>

/*
 * RTP payload types
 */
typedef enum {
    RTP_PCMU = 0,
    RTP_GSM = 3,
    RTP_G723 = 4,
    RTP_PCMA = 8,
    RTP_CN = 13,
    RTP_G729 = 18,
    RTP_TSE = 100,
    RTP_TSE_CISCO = 101
} rtp_type_t;

#define RTP_NSAMPLES_UNKNOWN  (-1)

/*
 * RTP data header
 */
typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int version:2;	/* protocol version */
    unsigned int p:1;		/* padding flag */
    unsigned int x:1;		/* header extension flag */
    unsigned int cc:4;		/* CSRC count */
    unsigned int m:1;		/* marker bit */
    unsigned int pt:7;		/* payload type */
#else
    unsigned int cc:4;		/* CSRC count */
    unsigned int x:1;		/* header extension flag */
    unsigned int p:1;		/* padding flag */
    unsigned int version:2;	/* protocol version */
    unsigned int pt:7;		/* payload type */
    unsigned int m:1;		/* marker bit */
#endif
    unsigned int seq:16;	/* sequence number */
    uint32_t ts;		/* timestamp */
    uint32_t ssrc;		/* synchronization source */
    uint32_t csrc[0];		/* optional CSRC list */
} rtp_hdr_t;

struct rtp_packet {
    size_t      size;

    struct sockaddr_storage raddr;
    socklen_t   rlen;
    size_t      data_size;
    int         data_offset;
    int         nsamples;
    uint32_t    ts;
    uint16_t    seq;
    int         resizeable;
    double      rtime;

    struct rtp_packet *next;
    struct rtp_packet *prev;

    /*
     * The packet, keep it the last member so that we can use
     * memcpy() only on portion that it's actually being
     * utilized.
     */
    union {
	rtp_hdr_t       header;
	unsigned char   buf[8192];
    };
};

#define	RTP_HDR_LEN(rhp)	(sizeof(*(rhp)) + ((rhp)->cc * sizeof((rhp)->csrc[0])))

void rtp_packet_parse(struct rtp_packet *);
struct rtp_packet *rtp_recv(int);

struct rtp_packet *rtp_packet_alloc();
void rtp_packet_free(struct rtp_packet *);
void rtp_packet_set_seq(struct rtp_packet *, uint16_t seq);
void rtp_packet_set_ts(struct rtp_packet *, uint32_t ts);

size_t rtp_samples2bytes(int codec_id, int nsamples);

#define ts_less(ts1, ts2) (((ts1) - (ts2)) > (uint32_t) (1 << 31))

#endif
