/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_stats;
struct rtpp_acct_pipe;
struct rtpp_proc_servers;
struct rtpp_session_ctor_args;

#define PIPE_RTP        1
#define PIPE_RTCP       2

#define PP_NAME(t)      (((t) == PIPE_RTP) ? "RTP" : "RTCP")

struct r_pipe_ctor_args {
    uint64_t seuid;
    struct rtpp_log *log;
    int pipe_type;
    const struct rtpp_session_ctor_args *session_cap;
};

DECLARE_CLASS(rtpp_pipe, const struct r_pipe_ctor_args *);

DECLARE_METHOD(rtpp_pipe, rtpp_pipe_get_ttl, int);
DECLARE_METHOD(rtpp_pipe, rtpp_pipe_decr_ttl, void);
DECLARE_METHOD(rtpp_pipe, rtpp_pipe_get_stats, void, struct rtpp_acct_pipe *);
DECLARE_METHOD(rtpp_pipe, rtpp_pipe_upd_cntrs, void, struct rtpp_acct_pipe *);

DECLARE_SMETHODS(rtpp_pipe)
{
    METHOD_ENTRY(rtpp_pipe_get_ttl, get_ttl);
    METHOD_ENTRY(rtpp_pipe_decr_ttl, decr_ttl);
    METHOD_ENTRY(rtpp_pipe_get_stats, get_stats);
    METHOD_ENTRY(rtpp_pipe_upd_cntrs, upd_cntrs);
};

DECLARE_CLASS_PUBTYPE(rtpp_pipe, {
    /* Session for caller [0] and callee [1] */
    struct rtpp_stream *stream[2];
    struct rtpp_pcount *pcount;
    /* UID */
    uint64_t ppuid;
    /* Session log */
    struct rtpp_log *log;

    struct rtpp_stats *rtpp_stats;

});
