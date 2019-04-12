/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
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

struct rtpp_acct;
struct rtpp_refcnt;
struct rtpps_pcount;
struct rtpp_pcnts_strm;
struct rtpa_stats;
struct rtpp_timestamp;

#if rtpp_acct_h_fin
#include "rtpp_acct_pipe.h"
#endif

struct rtpp_acct {
    uint64_t seuid;
    struct rtpp_acct_pipe rtp;
    struct rtpp_acct_pipe rtcp;
    struct rtpa_stats *rasto;
    struct rtpa_stats *rasta;
    struct rtpa_stats_jitter *jrasto;
    struct rtpa_stats_jitter *jrasta;
    char *call_id;
    char *from_tag;
    char *to_tag;
    /* Timestamp of session instantiation time */
    struct rtpp_timestamp *init_ts;
    /* Timestamp of session destruction time */
    struct rtpp_timestamp *destroy_ts;

    struct rtpp_refcnt *rcnt;
};

struct rtpp_acct *rtpp_acct_ctor(uint64_t);

#define rtpp_acct_OSIZE() (sizeof(struct rtpp_acct) + sizeof(struct rtpps_pcount) + \
  sizeof(struct rtpps_pcount) + sizeof(struct rtpp_pcnts_strm) + \
  sizeof(struct rtpp_pcnts_strm) + sizeof(struct rtpp_pcnts_strm) + \
  sizeof(struct rtpp_pcnts_strm) + sizeof(struct rtpa_stats) + \
  sizeof(struct rtpa_stats) + sizeof(struct rtpa_stats_jitter) + \
  sizeof(struct rtpa_stats_jitter))
