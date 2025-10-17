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
#include "rtpp_str.h"

struct rtpp_session;
struct rtpp_socket;
struct common_cmd_args;
struct sockaddr;
struct rtpp_timestamp;
struct rtpp_timeout_data;

struct rtpp_session {
    const rtpp_str_t *call_id;
    const rtpp_str_t *from_tag;
    const rtpp_str_t *from_tag_nmn;
    struct rtpp_log *log;
    struct rtpp_pipe *rtp;
    struct rtpp_pipe *rtcp;
    /* Session is complete, that is we received both request and reply */
    int complete;
    /* Flags: strong create/delete; weak ones */
    int strong;
    struct rtpp_timeout_data *timeout_data;
    /* UID */
    uint64_t seuid;

    struct rtpp_stats *rtpp_stats;

    /* Refcounter */
    struct rtpp_refcnt *rcnt;
};

struct rtpp_session_ctor_args {
    const struct rtpp_cfg *cfs;
    struct common_cmd_args *ccap;
    const struct rtpp_timestamp *dtime;
    const struct sockaddr **lia;
    int weak;
};

struct rtpp_stream_pair {
    struct rtpp_stream *in;
    struct rtpp_stream *out;
    int ret;
};

struct rtpp_cfg;

int compare_session_tags(const rtpp_str_t *, const rtpp_str_t *, unsigned *);
int find_stream(const struct rtpp_cfg *, const rtpp_str_t *, const rtpp_str_t *,
  const rtpp_str_t *, struct rtpp_session **);
struct rtpp_stream_pair get_rtcp_pair(const struct rtpp_session *,
  const struct rtpp_stream *) RTPP_EXPORT;

struct rtpp_session *rtpp_session_ctor(const struct rtpp_session_ctor_args *);
