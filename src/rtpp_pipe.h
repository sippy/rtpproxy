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

#ifndef _RTPP_PIPE_H_
#define _RTPP_PIPE_H_

struct rtpp_stats;
struct rtpp_pipe;
struct rtpp_acct_pipe;

#define PIPE_RTP        1
#define PIPE_RTCP       2

#define PP_NAME(t)      (((t) == PIPE_RTP) ? "RTP" : "RTCP")

DEFINE_METHOD(rtpp_pipe, rtpp_pipe_get_ttl, int);
DEFINE_METHOD(rtpp_pipe, rtpp_pipe_decr_ttl, void);
DEFINE_METHOD(rtpp_pipe, rtpp_pipe_get_stats, void, struct rtpp_acct_pipe *);
DEFINE_METHOD(rtpp_pipe, rtpp_pipe_upd_cntrs, void, struct rtpp_acct_pipe *);

struct rtpp_pipe {
    /* Session for caller [0] and callee [1] */
    struct rtpp_stream *stream[2];
    struct rtpp_pcount *pcount;
    /* UID */
    uint64_t ppuid;
    /* Session log */
    struct rtpp_log *log;

    struct rtpp_stats *rtpp_stats;
    struct rtpp_weakref_obj *servers_wrt;

    /* Refcounter */
    struct rtpp_refcnt *rcnt;

    METHOD_ENTRY(rtpp_pipe_get_ttl, get_ttl);
    METHOD_ENTRY(rtpp_pipe_decr_ttl, decr_ttl);
    METHOD_ENTRY(rtpp_pipe_get_stats, get_stats);
    METHOD_ENTRY(rtpp_pipe_upd_cntrs, upd_cntrs);
};

struct rtpp_pipe *rtpp_pipe_ctor(uint64_t, struct rtpp_weakref_obj *,
  struct rtpp_weakref_obj *, struct rtpp_log *,
  struct rtpp_stats *, int);

#endif
