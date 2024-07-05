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

struct packet_processor_if;
struct pkt_proc_ctx;
struct rtpp_refcnt;

enum pproc_action {
    PPROC_ACT_NOP = 0,
    PPROC_ACT_TEE = 1,
    PPROC_ACT_TAKE = 2,
    PPROC_ACT_DROP = 4
};

enum pproc_order {
    _PPROC_ORD_EMPTY  = 0,
    PPROC_ORD_RECV    = 1,
    PPROC_ORD_DECRYPT = 2,
    PPROC_ORD_CT_RECV = 3,
    PPROC_ORD_ANALYZE = 4,
    PPROC_ORD_RESIZE  = 5,
    PPROC_ORD_DECODE  = 6,
    PPROC_ORD_PLAY    = 7,
    PPROC_ORD_WITNESS = 8,
    PPROC_ORD_ENCODE  = 9,
    PPROC_ORD_CT_SEND = 10,
    PPROC_ORD_ENCRYPT = 11,
    PPROC_ORD_RELAY   = 12,
};

DEFINE_RAW_METHOD(pproc_taste, int, struct pkt_proc_ctx *);
DEFINE_RAW_METHOD(pproc_enqueue, enum pproc_action, const struct pkt_proc_ctx *);

struct packet_processor_if {
    const char *descr;
    struct rtpp_refcnt *rcnt;
    void *arg;
    void *key;
    pproc_taste_t taste;
    pproc_enqueue_t enqueue;
};
