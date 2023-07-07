/*
 * Copyright (c) 2023 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_cfg;
struct rtpp_anetio_cf;
struct rtpp_server;

DECLARE_CLASS(rtpp_proc_servers, const struct rtpp_cfg *,
  struct rtpp_anetio_cf *);

DECLARE_METHOD(rtpp_proc_servers, rtpp_proc_servers_reg, int,
  struct rtpp_server *, int);
DECLARE_METHOD(rtpp_proc_servers, rtpp_proc_servers_unreg, int, uint64_t);
DECLARE_METHOD(rtpp_proc_servers, rtpp_proc_servers_plr_start, int,
  uint64_t, double);

DECLARE_SMETHODS(rtpp_proc_servers)
{
    METHOD_ENTRY(rtpp_proc_servers_reg, reg);
    METHOD_ENTRY(rtpp_proc_servers_unreg, unreg);
    METHOD_ENTRY(rtpp_proc_servers_plr_start, plr_start);
};

DECLARE_CLASS_PUBTYPE(rtpp_proc_servers, {});
