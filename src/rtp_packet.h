/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTP_PACKET_H_
#define _RTP_PACKET_H_

struct rtp_info;
struct rtpp_wi;

struct rtp_packet {
    size_t      size;

    struct sockaddr_storage raddr;
    struct sockaddr_storage sendto;
    struct sockaddr_storage _laddr;
    struct sockaddr *laddr;
    int         lport;

    socklen_t   rlen;
    struct rtpp_timestamp rtime;

    struct rtp_packet *next;
    struct rtp_packet *prev;

    struct rtp_info *parsed;
    rtp_parser_err_t parse_result;

    struct rtpp_wi *wi;

    /*
     * The packet, keep it the last member so that we can use
     * memcpy() only on portion that it's actually being
     * utilized.
     */
    union {
        rtp_hdr_t       header;
        unsigned char   buf[8192];
    } data;
};

struct rtp_packet *rtp_packet_alloc();
void rtp_packet_free(struct rtp_packet *);
void rtp_packet_set_seq(struct rtp_packet *, uint16_t seq);
void rtp_packet_set_ts(struct rtp_packet *, uint32_t ts);

#define RTPP_DUP_HDRONLY 0x1    /* Do not copy payload, only headers, requires packet to be parsed */
void rtp_packet_dup(struct rtp_packet *, const struct rtp_packet *, int);

#endif
