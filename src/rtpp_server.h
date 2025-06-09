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

#pragma once

enum rtp_type;
#ifndef RTPP_FINCODE
struct rtpp_genuid;
struct rtpp_server_ctor_args {
    const char *name;
    enum rtp_type codec;
    int loop;
    int ptime;
    int result;
    struct rtpp_genuid *guid;
};
#else
struct rtpp_server_ctor_args;
#endif

DECLARE_CLASS(rtpp_server, struct rtpp_server_ctor_args *);

DECLARE_METHOD(rtpp_server, rtpp_server_get, struct rtp_packet *, double, int *);
DECLARE_METHOD(rtpp_server, rtpp_server_get_ssrc, uint32_t);
DECLARE_METHOD(rtpp_server, rtpp_server_set_ssrc, void, uint32_t);
DECLARE_METHOD(rtpp_server, rtpp_server_get_seq, uint16_t);
DECLARE_METHOD(rtpp_server, rtpp_server_set_seq, void, uint16_t);
DECLARE_METHOD(rtpp_server, rtpp_server_start, void, double);

DECLARE_SMETHODS(rtpp_server) {
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

DECLARE_CLASS_PUBTYPE(rtpp_server, {
    /* UID */
    uint64_t sruid;
    /* Weakref to the associated RTP stream */
    uint64_t stuid;
});

#define RTPP_SERV_OK     0
#define RTPP_SERV_NOENT -1
#define RTPP_SERV_NOMEM -2
#define RTPP_SERV_BADARG -3
