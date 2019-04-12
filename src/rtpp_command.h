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

#ifndef _RTPP_COMMAND_H_
#define _RTPP_COMMAND_H_

struct rtpp_command;
struct rtpp_command_stats;
struct cfg;
struct cfg_stable;
struct sockaddr;
struct rtpp_cmd_rcache;
struct rtpp_socket;
struct rtpp_ctrl_sock;
struct rtpp_timestamp;

#define GET_CMD_OK     (0)
#define GET_CMD_IOERR  (-1)
#define GET_CMD_EOF    (-2)
#define GET_CMD_ENOMEM (-3)
#define GET_CMD_EAGAIN (-4)
#define GET_CMD_INVAL (-5)

#define IS_WEIRD_ERRNO(e) ((e) == EINTR || (e) == EAGAIN || (e) == ENOBUFS)
#define RTPP_CMD_BUFLEN (8 * 1024)

int handle_command(struct cfg *, struct rtpp_command *);
void free_command(struct rtpp_command *);
struct rtpp_command *get_command(struct cfg *, struct rtpp_ctrl_sock *, int, int *,
  const struct rtpp_timestamp *, struct rtpp_command_stats *csp,
  struct rtpp_cmd_rcache *);
void reply_error(struct rtpp_command *cmd, int ecode);
void reply_ok(struct rtpp_command *cmd);
void reply_port(struct rtpp_command *cmd, int lport,
  struct sockaddr **lia);
void reply_number(struct rtpp_command *cmd, int number);
int rtpp_create_listener(struct cfg *, struct sockaddr *, int *,
  struct rtpp_socket **);
struct rtpp_command *rtpp_command_ctor(struct cfg *, int, const struct rtpp_timestamp *,
  struct rtpp_command_stats *, int);

void rtpc_doreply(struct rtpp_command *, char *, int, int);

#endif
