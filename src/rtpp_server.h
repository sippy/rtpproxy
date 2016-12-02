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
 */

#ifndef _RTP_SERVER_H_
#define _RTP_SERVER_H_

struct rtpp_server;
struct rtp_packet;

enum rtp_type;

DEFINE_METHOD(rtpp_server, rtpp_server_get, struct rtp_packet *, double, int *);
DEFINE_METHOD(rtpp_server, rtpp_server_get_ssrc, uint32_t);
DEFINE_METHOD(rtpp_server, rtpp_server_set_ssrc, void, uint32_t);
DEFINE_METHOD(rtpp_server, rtpp_server_get_seq, uint16_t);
DEFINE_METHOD(rtpp_server, rtpp_server_set_seq, void, uint16_t);
DEFINE_METHOD(rtpp_server, rtpp_server_start, void, double);

struct rtpp_server_smethods {
    /* Static methods */
    METHOD_ENTRY(rtpp_server_get, get);
    METHOD_ENTRY(rtpp_server_get_ssrc, get_ssrc);
    METHOD_ENTRY(rtpp_server_set_ssrc, set_ssrc);
    METHOD_ENTRY(rtpp_server_get_seq, get_seq);
    METHOD_ENTRY(rtpp_server_set_seq, set_seq);
    METHOD_ENTRY(rtpp_server_start, start);
};

#define	RTPS_LATER	(0)
#define	RTPS_EOF	(-1)
#define	RTPS_ERROR	(-2)
#define	RTPS_ENOMEM	(-3)

struct rtpp_server {
    /* Public methods */
    const struct rtpp_server_smethods *smethods;
    /* Refcounter */
    struct rtpp_refcnt *rcnt;
    /* UID */
    uint64_t sruid;
    /* Weakref to the associated RTP stream */
    uint64_t stuid;
};

struct rtpp_server *rtpp_server_ctor(const char *, enum rtp_type, int,  int);

#endif
