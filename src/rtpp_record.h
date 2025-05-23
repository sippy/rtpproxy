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

struct rtpp_session;
struct rtpp_stream;
struct rtp_packet;
struct rtpp_cfg;
struct pkt_proc_ctx;
struct rtpp_socket;

struct remote_copy_args {
    char rhost[NI_MAXHOST];
    const char *rport;
    int idx;
    const struct sockaddr *laddr;
    int lport;
    struct rtpp_socket *fds[2];
};

DECLARE_CLASS(rtpp_record, const struct rtpp_cfg *, const struct remote_copy_args *, struct rtpp_session *,
  const char *, int, int);

DECLARE_METHOD(rtpp_record, rtpp_record_write, void, const struct pkt_proc_ctx *);

DECLARE_SMETHODS(rtpp_record)
{
    METHOD_ENTRY(rtpp_record_write, pktwrite);
};

DECLARE_CLASS_PUBTYPE(rtpp_record, {});

#define RECORD_RTP  0
#define RECORD_RTCP 1
#define RECORD_BOTH 2
