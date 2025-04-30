/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpc_reply;

#if !defined(DECLARE_CLASS)
#error "rtpp_types.h" needs to be included
#endif

DECLARE_CLASS(rtpp_stats, void);

DECLARE_METHOD(rtpp_stats, rtpp_stats_getidxbyname, int, const char *);
DECLARE_METHOD(rtpp_stats, rtpp_stats_updatebyidx, int, int, uint64_t);
DECLARE_METHOD(rtpp_stats, rtpp_stats_updatebyname, int, const char *, uint64_t);
DECLARE_METHOD(rtpp_stats, rtpp_stats_updatebyname_d, int, const char *, double);
DECLARE_METHOD(rtpp_stats, rtpp_stats_getlvalbyname, int64_t, const char *);
DECLARE_METHOD(rtpp_stats, rtpp_stats_nstr, int, const char *, struct rtpc_reply *);
DECLARE_METHOD(rtpp_stats, rtpp_stats_getnstats, int);
DECLARE_METHOD(rtpp_stats, rtpp_stats_update_derived, void, double);

DECLARE_SMETHODS(rtpp_stats) {
    METHOD_ENTRY(rtpp_stats_getidxbyname, getidxbyname);
    METHOD_ENTRY(rtpp_stats_updatebyidx, updatebyidx);
    METHOD_ENTRY(rtpp_stats_updatebyname, updatebyname);
    METHOD_ENTRY(rtpp_stats_updatebyname_d, updatebyname_d);
    METHOD_ENTRY(rtpp_stats_getlvalbyname, getlvalbyname);
    METHOD_ENTRY(rtpp_stats_getnstats, getnstats);
    METHOD_ENTRY(rtpp_stats_nstr, nstr);
    METHOD_ENTRY(rtpp_stats_update_derived, update_derived);
};

DECLARE_CLASS_PUBTYPE(rtpp_stats, {
    struct rtpp_stats_priv *pvt;
});
