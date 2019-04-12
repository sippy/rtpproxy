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

#ifndef _RTPP_SESSION_H_
#define _RTPP_SESSION_H_

struct rtpp_session;
struct rtpp_socket;
struct common_cmd_args;
struct sockaddr;
struct rtpp_timestamp;

struct rtpp_timeout_data {
    char *notify_tag;
    struct rtpp_tnotify_target *notify_target;
};

struct rtpp_session {
    char *call_id;
    char *tag;
    char *tag_nomedianum;
    struct rtpp_log *log;
    struct rtpp_pipe *rtp;
    struct rtpp_pipe *rtcp;
    /* Session is complete, that is we received both request and reply */
    int complete;
    /* Flags: strong create/delete; weak ones */
    int strong;
    struct rtpp_timeout_data timeout_data;
    /* UID */
    uint64_t seuid;

    struct rtpp_stats *rtpp_stats;
    struct rtpp_weakref_obj *servers_wrt;

    /* Refcounter */
    struct rtpp_refcnt *rcnt;
};

struct cfg;
struct cfg_stable;

int compare_session_tags(const char *, const char *, unsigned *);
int find_stream(struct cfg *, const char *, const char *, const char *,
  struct rtpp_session **);

struct rtpp_session *rtpp_session_ctor(struct rtpp_cfg_stable *,
  struct common_cmd_args *, const struct rtpp_timestamp *,
  struct sockaddr **, int, int, struct rtpp_socket **);

#endif
