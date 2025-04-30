/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpps_pcount;
struct rtpp_codeptr;
struct rtpp_log;

DECLARE_CLASS(rtpp_pcount, void);

DECLARE_METHOD(rtpp_pcount, rtpp_pcount_reg_reld, void);
DECLARE_METHOD(rtpp_pcount, rtpp_pcount_reg_drop, void, const struct rtpp_codeptr *);
DECLARE_METHOD(rtpp_pcount, rtpp_pcount_log_drops, void, struct rtpp_log *);
DECLARE_METHOD(rtpp_pcount, rtpp_pcount_reg_ignr, void);
DECLARE_METHOD(rtpp_pcount, rtpp_pcount_get_stats, void,
  struct rtpps_pcount *);

struct rtpps_pcount {
    unsigned long nrelayed;
    unsigned long ndropped;
    unsigned long nignored;
};

DECLARE_SMETHODS(rtpp_pcount) {
    METHOD_ENTRY(rtpp_pcount_reg_reld, reg_reld);
    METHOD_ENTRY(rtpp_pcount_reg_drop, reg_drop);
    METHOD_ENTRY(rtpp_pcount_log_drops, log_drops);
    METHOD_ENTRY(rtpp_pcount_reg_ignr, reg_ignr);
    METHOD_ENTRY(rtpp_pcount_get_stats, get_stats);
};

DECLARE_CLASS_PUBTYPE(rtpp_pcount, {});
