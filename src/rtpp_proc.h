/*
 * Copyright (c) 2010 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_PROC_H_
#define _RTPP_PROC_H_

struct sthread_args;
struct rtpp_polltbl;
struct rtpp_timestamp;
struct rtpp_cfg;
struct epoll_event;

struct rtpp_proc_stat {
    uint64_t cnt;
    int cnt_idx;
};

#define FLUSH_STAT(sobj, st)    { \
    if ((st).cnt > 0) { \
        CALL_SMETHOD(sobj, updatebyidx, (st).cnt_idx, (st).cnt); \
        (st).cnt = 0; \
    } \
}

struct rtpp_proc_rstats {
    struct rtpp_proc_stat npkts_rcvd;
    struct rtpp_proc_stat npkts_relayed;
    struct rtpp_proc_stat npkts_resizer_in;
    struct rtpp_proc_stat npkts_resizer_out;
    struct rtpp_proc_stat npkts_resizer_discard;
    struct rtpp_proc_stat npkts_discard;
};

void process_rtp_servers(const struct rtpp_cfg *, double,
  struct sthread_args *, struct rtpp_proc_rstats *);
void process_rtp_only(const struct rtpp_cfg *,
  struct rtpp_polltbl *, const struct rtpp_timestamp *, int,
  struct sthread_args *sender, struct rtpp_proc_rstats *,
  struct epoll_event *, int);

#endif
