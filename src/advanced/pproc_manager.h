/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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

struct pproc_manager;
struct packet_processor_if;
struct rtpp_session;
struct rtpp_stream;
struct rtp_packet;
struct rtpp_stats;

enum pproc_action;
enum pproc_order;

#define PPROC_FLAG_LGEN (1 << 0)

struct pkt_proc_ctx {
    struct rtpp_stream *strmp_in;
    struct rtpp_stream *strmp_out;
    struct rtp_packet *pktp;
    struct rtpp_proc_rstats *rsp;
    const struct packet_processor_if *pproc;
    void *auxp;
    unsigned int flags;
};

DEFINE_METHOD(pproc_manager, pproc_manager_reg, int, enum pproc_order, const struct packet_processor_if *);
DEFINE_METHOD(pproc_manager, pproc_manager_unreg, void, void *);
DEFINE_METHOD(pproc_manager, pproc_manager_handle, enum pproc_action, struct pkt_proc_ctx *);
DEFINE_METHOD(pproc_manager, pproc_manager_handleat, enum pproc_action, struct pkt_proc_ctx *,
  enum pproc_order);
DEFINE_METHOD(pproc_manager, pproc_manager_lookup, const struct packet_processor_if *,
  void *);
DEFINE_METHOD(pproc_manager, pproc_manager_clone, struct pproc_manager *);
DEFINE_METHOD(pproc_manager, pproc_manager_reg_drop, void);

struct pproc_manager_smethods
{
    METHOD_ENTRY(pproc_manager_reg, reg);
    METHOD_ENTRY(pproc_manager_unreg, unreg);
    METHOD_ENTRY(pproc_manager_handle, handle);
    METHOD_ENTRY(pproc_manager_handleat, handleat);
    METHOD_ENTRY(pproc_manager_lookup, lookup);
    METHOD_ENTRY(pproc_manager_clone, clone);
    METHOD_ENTRY(pproc_manager_reg_drop, reg_drop);
};

struct pproc_manager {
    struct rtpp_refcnt *rcnt;
    struct pproc_manager *reverse;
#if defined(RTPP_DEBUG)
    const struct pproc_manager_smethods * smethods;
#endif
};

struct pproc_manager *rtpp_pproc_mgr_ctor(struct rtpp_stats *);
