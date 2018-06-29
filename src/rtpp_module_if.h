/*
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_module_if;
struct rtpp_refcnt;
struct rtpp_acct;
struct rtpp_acct_rtcp;
struct rtpp_log;
struct rtpp_cfg_stable;
struct rtpp_module_conf;

DEFINE_METHOD(rtpp_module_if, rtpp_module_if_load, int, struct rtpp_cfg_stable *,
  struct rtpp_log *);
DEFINE_METHOD(rtpp_module_if, rtpp_module_if_config, int);
DEFINE_METHOD(rtpp_module_if, rtpp_module_if_start, int);
DEFINE_METHOD(rtpp_module_if, rtpp_module_if_do_acct, void,
  struct rtpp_acct *);
DEFINE_METHOD(rtpp_module_if, rtpp_module_if_do_acct_rtcp, void,
  struct rtpp_acct_rtcp *);
DEFINE_METHOD(rtpp_module_if, rtpp_module_if_get_mconf, int,
  struct rtpp_module_conf **);

struct rtpp_module_if {
    struct rtpp_type_linkable t;
    struct rtpp_refcnt *rcnt;
    METHOD_ENTRY(rtpp_module_if_load, load);
    METHOD_ENTRY(rtpp_module_if_config, config);
    METHOD_ENTRY(rtpp_module_if_start, start);
    METHOD_ENTRY(rtpp_module_if_do_acct, do_acct);
    METHOD_ENTRY(rtpp_module_if_do_acct_rtcp, do_acct_rtcp);
    METHOD_ENTRY(rtpp_module_if_get_mconf, get_mconf);
};

struct rtpp_module_if *rtpp_module_if_ctor(const char *);
