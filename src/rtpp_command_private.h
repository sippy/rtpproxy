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

#pragma once

#include "rtpp_str.h"

struct rtpp_timestamp;
struct rtpc_reply;
struct record_opts;

enum rtpp_cmd_op {DELETE, RECORD, PLAY, NOPLAY, COPY, UPDATE, LOOKUP, INFO,
  QUERY, VER_FEATURE, GET_VER, DELETE_ALL, GET_STATS, NORECORD};

struct common_cmd_args {
    enum rtpp_cmd_op op;
    const char *rname;
    const char *hint;
    const rtpp_str_t *call_id;
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
    union {
        struct ul_opts *ul;
        struct play_opts *play;
        struct delete_opts *delete;
        struct record_opts *record;
        void *ptr;
    } opts;
};

#define MAX_SUBC_NUM 16

struct after_success_h_args;
struct rtpp_subc_ctx;

DEFINE_RAW_METHOD(after_success, int, const struct after_success_h_args *,
  const struct rtpp_subc_ctx *);

struct after_success_h_args {
    void *stat;
    void *dyn;

};

struct after_success_h {
    after_success_t handler;
    struct after_success_h_args args;
};

struct rtpp_command {
    struct rtpp_refcnt *rcnt;
    char buf[RTPP_CMD_BUFLEN];
    struct rtpp_command_args args;
    struct {
        struct rtpp_command_args args[MAX_SUBC_NUM];
        struct rtpp_subc_resp res[MAX_SUBC_NUM];
        int n;
    } subc;
    struct sockaddr *laddr;
    const struct rtpp_timestamp *dtime;
    struct common_cmd_args cca;
    int no_glock;
    struct rtpp_session *sp;
    struct rtpp_log *glog;
    struct rtpc_reply *reply;
    struct after_success_h after_success[MAX_SUBC_NUM];
};
