/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_COMMAND_PRIVATE_H_
#define _RTPP_COMMAND_PRIVATE_H_

struct rtpp_timestamp;

struct rtpp_command_stat {
    uint64_t cnt;
    int cnt_idx;
};

struct rtpp_command_stats {
    struct rtpp_command_stat ncmds_rcvd;
    struct rtpp_command_stat ncmds_rcvd_ndups;
    struct rtpp_command_stat ncmds_succd;
    struct rtpp_command_stat ncmds_errs;
    struct rtpp_command_stat ncmds_repld;

    struct rtpp_command_stat nsess_complete;
    struct rtpp_command_stat nsess_created;

    struct rtpp_command_stat nplrs_created;
    struct rtpp_command_stat nplrs_destroyed;
};

#define RTPC_MAX_ARGC   20

enum rtpp_cmd_op {DELETE, RECORD, PLAY, NOPLAY, COPY, UPDATE, LOOKUP, INFO,
  QUERY, VER_FEATURE, GET_VER, DELETE_ALL, GET_STATS};

struct common_cmd_args {
    enum rtpp_cmd_op op;
    const char *rname;
    const char *hint;
    char *call_id;
    char *from_tag;
    char *to_tag;
    union {
        struct ul_opts *ul;
        struct play_opts *play;
        struct delete_opts *delete;
        void *ptr;
    } opts;
};

struct rtpp_command
{
    char buf[RTPP_CMD_BUFLEN];
    char buf_t[256];
    char *argv[RTPC_MAX_ARGC];
    int argc;
    struct sockaddr_storage raddr;
    struct sockaddr *laddr;
    socklen_t rlen;
    const struct rtpp_timestamp *dtime;
    struct rtpp_command_stats *csp;
    struct common_cmd_args cca;
    int no_glock;
    struct rtpp_session *sp;
    struct rtpp_log *glog;
};

#endif
