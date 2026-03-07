/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_COMMAND_UL_H_
#define _RTPP_COMMAND_UL_H_

#include "rtpp_str.h"

struct rtpp_cfg;
struct ul_opts;
struct ul_reply;
struct rtpp_command;
struct rtpp_session;
struct rtpp_subc_ctx;
struct rtpp_subc_resp;
struct rtpp_command_args;
struct after_success_h;
struct rtpp_command_stats;
struct rtpp_sockaddr;

struct rtpp_command_ul_pcmd {
    int op;
    const char *cmods;
    const rtpp_str_t *call_id;
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
    const rtpp_str_t *addr;
    const rtpp_str_t *port;
    const rtpp_str_t *notify_socket;
    rtpp_str_const_t notify_tag;
    int has_notify;
};

struct ul_opts *rtpp_command_ul_opts_parse(const struct rtpp_cfg *,
  struct rtpp_command *cmd);
struct ul_opts *rtpp_command_ul_opts_parse_inner(const struct rtpp_cfg *,
  struct rtpp_command *, struct rtpp_command_ul_pcmd *, int *);
void rtpp_command_ul_opts_free(struct ul_opts *ulop);
int rtpp_command_ul_handle(const struct rtpp_cfg *, struct rtpp_command *,
  int);
int rtpp_command_ul_handle_impl(const struct rtpp_cfg *,
  struct rtpp_command *, int, struct rtpp_subc_resp *,
  struct rtpp_command_stats *, const struct rtpp_sockaddr *);
void ul_reply_port(struct rtpp_command *cmd,
  struct ul_reply *ulr);

#endif
