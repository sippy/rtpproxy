/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2024 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#pragma once

struct rtpp_command_ctx;
struct sockaddr;

#define IS_WEIRD_ERRNO(e) ((e) == EINTR || (e) == EAGAIN || (e) == ENOBUFS)

DECLARE_CLASS(rtpc_reply, const struct rtpp_command_ctx *);

DECLARE_METHOD(rtpc_reply, rtpc_reply_deliver_error, void, int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_deliver_ok, void);
DECLARE_METHOD(rtpc_reply, rtpc_reply_deliver_number, void, int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_deliver_port_addr, int, const struct sockaddr *,
  int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_append_port_addr, int, const struct sockaddr *,
  int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_append_port_addr_s, int, const char *,
  int, int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_deliver, void, int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_append, int, const char *,
  int, int);
DECLARE_METHOD(rtpc_reply, rtpc_reply_appendf, int, const char *,
  ...) __attribute__ ((format (printf, 2, 3)));
DECLARE_METHOD(rtpc_reply, rtpc_reply_commit, void);
DECLARE_METHOD(rtpc_reply, rtpc_reply_reserve, int, int);

DECLARE_SMETHODS(rtpc_reply)
{
    METHOD_ENTRY(rtpc_reply_deliver_error, deliver_error);
    METHOD_ENTRY(rtpc_reply_deliver_ok, deliver_ok);
    METHOD_ENTRY(rtpc_reply_deliver_number, deliver_number);
    METHOD_ENTRY(rtpc_reply_deliver_port_addr, deliver_port_addr);
    METHOD_ENTRY(rtpc_reply_append_port_addr, append_port_addr);
    METHOD_ENTRY(rtpc_reply_append_port_addr_s, append_port_addr_s);
    METHOD_ENTRY(rtpc_reply_deliver, deliver);
    METHOD_ENTRY(rtpc_reply_append, append);
    METHOD_ENTRY(rtpc_reply_appendf, appendf);
    METHOD_ENTRY(rtpc_reply_commit, commit);
    METHOD_ENTRY(rtpc_reply_reserve, reserve);
};

DECLARE_CLASS_PUBTYPE(rtpc_reply, {});
