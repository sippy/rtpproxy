/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_refcnt;
struct rtpp_cmd_rcache;

DEFINE_METHOD(rtpp_cmd_rcache, rcache_insert, void, const rtpp_str_t *,
  const rtpp_str_t *, struct rtpp_refcnt *, double);
DEFINE_METHOD(rtpp_cmd_rcache, rcache_lookup, struct rtpp_cmd_rcache_entry *,
  const rtpp_str_t *);
DEFINE_METHOD(rtpp_cmd_rcache, rcache_shutdown, void);

struct rtpp_cmd_rcache {
    METHOD_ENTRY(rcache_insert, insert);
    METHOD_ENTRY(rcache_lookup, lookup);
    METHOD_ENTRY(rcache_shutdown, shutdown);
    struct rtpp_refcnt *rcnt;
};

struct rtpp_cmd_rcache_entry {
    struct rtpp_refcnt *rcnt;
    const rtpp_str_const_t * reply;
};

struct rtpp_timed;

struct rtpp_cmd_rcache *rtpp_cmd_rcache_ctor(struct rtpp_timed *, double);
