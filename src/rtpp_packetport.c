/*
 * Copyright (c) 2026 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "SPMCQueue.h"

#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_codeptr.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_hash_table.h"
#include "rtpp_queue.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"
#include "rtpp_wi_sgnl.h"
#include "rtpp_network.h"
#include "rtpp_netaddr.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtp_packet_priv.h"
#include "rtpp_packetport.h"
#include "rtpp_packet_ext.h"
#include "rtpp_pipe.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"
#include "librtpproxy.h"

#define EXT2PVT(pubp, pvtp) \
    (pvtp) = (typeof(pvtp))((char *)(pubp) - offsetof(typeof(*(pvtp)), ext))

#define RTPP_PACKETPORT_PRIV_ID UINT64_C(0x6394a0d34f12758b)
#define RTPP_PACKETPORT_OUT_PORT0 2
#define RTPP_PACKETPORT_IN_PORT0 2
#define RTPP_PPSIG_TERM 0
#define RTPP_PPSIG_NUDGE 1

static const struct timespec rtpp_packetport_tick = {
    .tv_sec = 0,
    .tv_nsec = 10000000L,
};

struct rtpp_packetport_int_priv {
    struct rtpp_packetport_int pub;
    struct rtpp_packetport ext;
    uint64_t id;
    unsigned int capacity;
    _Atomic(unsigned int) out_port;
    _Atomic(unsigned int) in_port;
    pthread_t worker_id;
    struct rtpp_queue *pqueue;
    struct rtpp_hash_table *streams_ht;
    struct rtpp_wi *sigterm;
    struct rtpp_wi **wi_batch;
    void **out_batch;
};

struct rtpp_packet_ext_int {
    struct rtpp_refcnt *rcnt;
    struct rtp_packet_ext pub;
    int own_data;
    struct rtp_packet *pktp;
};

struct rtpp_packet_ext_l {
    struct rtpp_packet_ext_int pxi;
};

struct rtpp_packet_ext_o {
    struct rtpp_packet_ext_int pxi;
    struct rtp_packet_full pktp;
};

static void rtpp_packetport_dtor_obj(struct rtpp_packetport_int_priv *);
static void *rtpp_packetport_run(void *);
static int rtpp_packetport_send_pkt_na(struct rtpp_packetport_int *,
  unsigned int, struct rtp_packet *);
static unsigned int rtpp_packetport_next_in_port_int(struct rtpp_packetport_int *);
static unsigned int rtpp_packetport_next_out_port_int(struct rtpp_packetport_int *);
static int rtpp_packetport_reg_stream(struct rtpp_packetport_int *,
  unsigned int, struct rtpp_stream *);
static int rtpp_packetport_reg_streams(struct rtpp_packetport_int *,
  struct rtpp_session *, int, unsigned int);
static void rtpp_packetport_unreg_stream(struct rtpp_packetport_int *,
  unsigned int);
static int rtpp_packetport_queue(struct SPMCQueue *, struct rtp_packet_ext *);
static struct rtpp_wi *rtpp_packetport_get_wi(struct rtp_packet *,
  unsigned int);
static int rtpp_packetport_queue_wi(struct rtpp_packetport_int_priv *,
  struct rtpp_wi *);
static int rtpp_packetport_proc_wi_batch(struct rtpp_packetport_int_priv *,
  struct rtpp_wi **, int);
static void rtpp_packetport_drain_queue(struct SPMCQueue *);
static void rtpp_packetport_drain_out(struct rtpp_packetport_int_priv *);
static int rtpp_packetport_ismapped(const void *);
static int rtpp_packetport_nudge(struct rtpp_packetport_int_priv *);
static unsigned int rtpp_packetport_nport_alloc(_Atomic(unsigned int) *);
static enum rtpp_ht_key_types rtpp_packetport_htkey_type(void);
static void rtpp_packetport_deadline_step(struct timespec *);

DEFINE_SMETHODS(rtpp_packetport_int,
    .send_pkt_na = &rtpp_packetport_send_pkt_na,
    .next_in_port = &rtpp_packetport_next_in_port_int,
    .next_out_port = &rtpp_packetport_next_out_port_int,
    .reg_stream = &rtpp_packetport_reg_stream,
    .reg_streams = &rtpp_packetport_reg_streams,
    .unreg_stream = &rtpp_packetport_unreg_stream,
);

struct rtp_packet_ext *
rtp_packet_ext_ctor(int dlen, unsigned int port, const void *data,
  rtp_packet_ext_dtor_t dtor_f, void *dtor_arg)
{
    struct rtpp_packet_ext_o *pktxop;

    assert(dlen > 0);
    assert(dlen <= MAX_RPKT_LEN);
    pktxop = rtpp_rzmalloc(sizeof(*pktxop), offsetof(struct rtpp_packet_ext_o,
      pxi.rcnt));
    if (pktxop == NULL) {
        return (NULL);
    }
    if (dtor_f != NULL) {
        RTPP_OBJ_DTOR_ATTACH_s(&pktxop->pxi, (rtpp_refcnt_dtor_t)dtor_f,
          dtor_arg);
    }
    pktxop->pxi.own_data = 1;
    pktxop->pxi.pktp = &pktxop->pktp.pub;
    pktxop->pxi.pub.data = pktxop->pktp.pub.data.buf;
    pktxop->pxi.pub.dlen = dlen;
    pktxop->pxi.pub.port = port;
    pktxop->pktp.pub.rcnt = pktxop->pxi.rcnt;
    pktxop->pktp.pub.size = dlen;
    pktxop->pktp.pub.parse_result = RTP_PARSER_NOTPARSED;
    if (data != NULL) {
        memcpy(pktxop->pktp.pub.data.buf, data, (size_t)dlen);
    }
    return (&pktxop->pxi.pub);
}

void
rtp_packet_ext_dtor(struct rtp_packet_ext *pktxp)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    RTPP_OBJ_DECREF(pktxip);
}

struct rtp_packet_ext *
rtpp_packet_ext_link(struct rtp_packet *pktp, unsigned int port)
{
    struct rtpp_packet_ext_l *pktxlp;

    pktxlp = rtpp_rzmalloc(sizeof(*pktxlp), offsetof(struct rtpp_packet_ext_l,
      pxi.rcnt));
    if (pktxlp == NULL) {
        return (NULL);
    }
    RTPP_OBJ_BORROW_s(&pktxlp->pxi, pktp);
    pktxlp->pxi.pktp = pktp;
    pktxlp->pxi.pub.data = pktp->data.buf;
    pktxlp->pxi.pub.dlen = pktp->size;
    pktxlp->pxi.pub.port = port;
    return (&pktxlp->pxi.pub);
}

struct rtp_packet *
rtpp_packet_ext_get_pkt(struct rtp_packet_ext *pktxp)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    if (pktxip->pktp != NULL && pktxip->own_data != 0) {
        pktxip->pktp->size = pktxp->dlen;
        pktxp->data = pktxip->pktp->data.buf;
    }
    return (pktxip->pktp);
}

int
rtpp_packet_ext_owns_data(struct rtp_packet_ext *pktxp)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    return (pktxip->own_data);
}

double
rtpp_packet_ext_get_rtime_wall(const struct rtp_packet_ext *pktxp)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    return (pktxip->pktp->rtime.wall);
}

double
rtpp_packet_ext_get_rtime_mono(const struct rtp_packet_ext *pktxp)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    return (pktxip->pktp->rtime.mono);
}

void
rtpp_packet_ext_set_rtime(struct rtp_packet_ext *pktxp, double wall, double mono)
{
    struct rtpp_packet_ext_int *pktxip;

    PUB2PVT(pktxp, pktxip);
    pktxip->pktp->rtime.wall = wall;
    pktxip->pktp->rtime.mono = mono;
}

struct rtpp_packetport *
rtpp_packetport_ctor(unsigned int capacity)
{
    struct rtpp_packetport_int_priv *pvt;

    _Static_assert(sizeof(unsigned int) == sizeof(uint32_t) ||
      sizeof(unsigned int) == sizeof(uint64_t),
      "unsupported unsigned int width");
    assert(capacity > 0);
    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->capacity = capacity;
    pvt->ext.in = create_queue((size_t)capacity);
    if (pvt->ext.in == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH_s(&pvt->pub, destroy_queue, pvt->ext.in);
    pvt->ext.out = create_queue((size_t)capacity);
    if (pvt->ext.out == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH_s(&pvt->pub, destroy_queue, pvt->ext.out);
    pvt->pqueue = rtpp_queue_init(capacity + 1, "rtpp_packetport(%p)", pvt);
    if (pvt->pqueue == NULL) {
        goto e0;
    }
    rtpp_queue_setmaxlen(pvt->pqueue, capacity + 1);
    RTPP_OBJ_DTOR_ATTACH_s(&pvt->pub, rtpp_queue_destroy, pvt->pqueue);
    pvt->wi_batch = rtpp_zmalloc(sizeof(pvt->wi_batch[0]) * (size_t)capacity);
    if (pvt->wi_batch == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH_s(&pvt->pub, rtpp_sys_free, pvt->wi_batch);
    pvt->out_batch = rtpp_zmalloc(sizeof(pvt->out_batch[0]) * (size_t)capacity);
    if (pvt->out_batch == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH_s(&pvt->pub, rtpp_sys_free, pvt->out_batch);
    pvt->streams_ht = rtpp_hash_table_ctor(rtpp_packetport_htkey_type(),
      RTPP_HT_NODUPS);
    if (pvt->streams_ht == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH_OBJ_s(&pvt->pub, pvt->streams_ht);
    pvt->sigterm = rtpp_wi_malloc_sgnl(RTPP_PPSIG_TERM, NULL, 0);
    if (pvt->sigterm == NULL) {
        goto e0;
    }
    if (pthread_create(&pvt->worker_id, NULL, &rtpp_packetport_run, pvt) != 0) {
        RTPP_OBJ_DECREF(pvt->sigterm);
        goto e0;
    }
    pvt->id = RTPP_PACKETPORT_PRIV_ID;
    atomic_init(&pvt->out_port, (unsigned int)RTPP_PACKETPORT_OUT_PORT0);
    atomic_init(&pvt->in_port, (unsigned int)RTPP_PACKETPORT_IN_PORT0);
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_packetport_dtor_obj);
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(pvt->worker_id, "rtpp_packetport");
#endif
    return (&pvt->ext);
e0:
    RTPP_OBJ_DECREF(&pvt->pub);
    return (NULL);
}

void
rtpp_packetport_push(struct rtpp_packetport *ext, struct rtp_packet_ext *pktxp)
{
    struct rtpp_packetport_int_priv *pvt;

    EXT2PVT(ext, pvt);
    if (rtpp_packetport_queue(pvt->ext.out, pktxp) != 0) {
        rtp_packet_ext_dtor(pktxp);
    }
}

int
rtpp_packetport_try_push(struct rtpp_packetport *ext, struct rtp_packet_ext *pktxp)
{
    struct rtpp_packetport_int_priv *pvt;

    EXT2PVT(ext, pvt);
    return (try_push(pvt->ext.out, pktxp) ? 0 : -1);
}

struct rtpp_packetport_int *
rtpp_packetport_get_int(struct rtpp_packetport *ext)
{
    struct rtpp_packetport_int_priv *pvt;

    EXT2PVT(ext, pvt);
    if (!rtpp_packetport_ismapped(pvt)) {
        return (NULL);
    }
    if (pvt->id != RTPP_PACKETPORT_PRIV_ID) {
        return (NULL);
    }
    RTPP_OBJ_INCREF(&pvt->pub);
    return (&pvt->pub);
}

struct rtp_packet_ext *
rtpp_packetport_try_pop(struct rtpp_packetport *ext)
{
    void *pktxp;

    if (!try_pop(ext->in, &pktxp)) {
        return (NULL);
    }
    return (pktxp);
}

size_t
rtpp_packetport_try_pop_many(struct rtpp_packetport *ext,
  struct rtp_packet_ext **pktxps, size_t max_items)
{

    return (try_pop_many(ext->in, (void **)pktxps, max_items));
}

unsigned int
rtpp_packetport_next_in_port(struct rtpp_packetport *ext)
{
    struct rtpp_packetport_int_priv *pvt;

    EXT2PVT(ext, pvt);
    return (CALL_SMETHOD(&pvt->pub, next_in_port));
}

void
rtpp_packetport_dtor(struct rtpp_packetport *ext)
{
    struct rtpp_packetport_int_priv *pvt;

    EXT2PVT(ext, pvt);
    RTPP_OBJ_DECREF(&pvt->pub);
}

static void
rtpp_packetport_dtor_obj(struct rtpp_packetport_int_priv *pvt)
{

    pvt->id = 0;
    rtpp_queue_put_item(pvt->sigterm, pvt->pqueue);
    pthread_join(pvt->worker_id, NULL);
    rtpp_packetport_drain_queue(pvt->ext.out);
    rtpp_packetport_drain_queue(pvt->ext.in);
}

static void *
rtpp_packetport_run(void *argp)
{
    struct rtpp_packetport_int_priv *pvt;
    struct timespec deadline, *ddp = NULL;
    int nwis, qlen = 0;

    pvt = argp;
    for (;;) {
        if (qlen == 0)
            qlen = CALL_SMETHOD(pvt->streams_ht, get_length) > 0 ? 16 : 0;
        if (qlen > 0) {
            rtpp_packetport_drain_out(pvt);
            if (ddp == NULL) {
                ddp = &deadline;
                dtime2mtimespec(getdtime(), ddp);
            }
            rtpp_packetport_deadline_step(ddp);
            nwis = rtpp_queue_get_items_by(pvt->pqueue, pvt->wi_batch,
              (int)pvt->capacity, ddp, NULL);
            qlen -= 1;
        } else {
            ddp = NULL;
            nwis = rtpp_queue_get_items(pvt->pqueue, pvt->wi_batch,
              (int)pvt->capacity, 0);
        }
        if (nwis == 0)
            continue;
        if (rtpp_packetport_proc_wi_batch(pvt, pvt->wi_batch, nwis) != 0)
            break;
    }
    return (NULL);
}

static int
rtpp_packetport_send_pkt_na(struct rtpp_packetport_int *self,
  unsigned int rport, struct rtp_packet *pkt)
{
    struct rtpp_wi *wi;
    struct rtpp_packetport_int_priv *pvt;

    PUB2PVT(self, pvt);
    wi = rtpp_packetport_get_wi(pkt, rport);
    if (wi == NULL) {
        return (-1);
    }
    if (rtpp_packetport_queue_wi(pvt, wi) != 0) {
        RTPP_OBJ_DECREF(wi);
        return (-1);
    }
    return (0);
}

static unsigned int
rtpp_packetport_next_in_port_int(struct rtpp_packetport_int *self)
{
    struct rtpp_packetport_int_priv *pvt;

    PUB2PVT(self, pvt);
    return (rtpp_packetport_nport_alloc(&pvt->in_port));
}

static unsigned int
rtpp_packetport_next_out_port_int(struct rtpp_packetport_int *self)
{
    struct rtpp_packetport_int_priv *pvt;

    PUB2PVT(self, pvt);
    return (rtpp_packetport_nport_alloc(&pvt->out_port));
}

static int
rtpp_packetport_reg_stream(struct rtpp_packetport_int *self, unsigned int port,
  struct rtpp_stream *stp)
{
    struct rtpp_packetport_int_priv *pvt;

    if (!rtpp_is_lib)
        abort();

    PUB2PVT(self, pvt);
    if (CALL_SMETHOD(pvt->streams_ht, append_refcnt, &port, stp->rcnt,
      NULL) == NULL) {
        return (-1);
    }
    if (rtpp_packetport_nudge(pvt) != 0) {
        (void)CALL_SMETHOD(pvt->streams_ht, remove_by_key, &port, NULL);
        return (-1);
    }
    return (0);
}

static int
rtpp_packetport_reg_streams(struct rtpp_packetport_int *self,
  struct rtpp_session *spa, int sidx, unsigned int lport)
{

    if (CALL_SMETHOD(self, reg_stream, lport, spa->rtp->stream[sidx]) != 0) {
        return (-1);
    }
    if (CALL_SMETHOD(self, reg_stream, lport + 1,
      spa->rtcp->stream[sidx]) != 0) {
        CALL_SMETHOD(self, unreg_stream, lport);
        return (-1);
    }
    return (0);
}

static void
rtpp_packetport_unreg_stream(struct rtpp_packetport_int *self, unsigned int port)
{
    struct rtpp_packetport_int_priv *pvt;

    PUB2PVT(self, pvt);
    (void)CALL_SMETHOD(pvt->streams_ht, remove_by_key, &port, NULL);
}

static int
rtpp_packetport_queue(struct SPMCQueue *queue, struct rtp_packet_ext *pktxp)
{
    void *dropxp;

    while (!try_push(queue, pktxp)) {
        if (!try_pop(queue, &dropxp)) {
            return (-1);
        }
        rtp_packet_ext_dtor(dropxp);
    }
    return (0);
}

static struct rtpp_wi *
rtpp_packetport_get_wi(struct rtp_packet *pkt, unsigned int port)
{
    struct rtpp_wi *wi;
    struct rtpp_wi_pvt *wipp;

    RTPP_OBJ_INCREF(pkt);
    wi = rtp_packet_get_wi(pkt);
    if (wi == NULL) {
        RTPP_OBJ_DECREF(pkt);
        return (NULL);
    }
    PUB2PVT(wi, wipp);
    wipp->pub = (const struct rtpp_wi) {
        .wi_type = RTPP_WI_TYPE_DATA,
        .rcnt = pkt->rcnt
    };
    wipp->sendargs.sock = port;
    wipp->sendargs.msg = pkt;
    return (wi);
}

static int
rtpp_packetport_queue_wi(struct rtpp_packetport_int_priv *pvt, struct rtpp_wi *wi)
{

    return (rtpp_queue_put_item(wi, pvt->pqueue));
}

static int
rtpp_packetport_proc_wi_batch(struct rtpp_packetport_int_priv *pvt,
  struct rtpp_wi **wis, int nwis)
{
    struct rtpp_wi_pvt *wipp;
    struct rtp_packet_ext *pktxp;
    struct rtp_packet *pktp;
    int i, signum, term_seen;

    term_seen = 0;
    for (i = 0; i < nwis; i++) {
        if (wis[i]->wi_type == RTPP_WI_TYPE_SGNL) {
            signum = rtpp_wi_sgnl_get_signum(wis[i]);
            if (signum == RTPP_PPSIG_TERM) {
                term_seen = 1;
                break;
            }
            RTPP_DBG_ASSERT(signum == RTPP_PPSIG_NUDGE);
            continue;
        }
        PUB2PVT(wis[i], wipp);
        pktp = (struct rtp_packet *)wipp->sendargs.msg;
        pktxp = rtpp_packet_ext_link(pktp, wipp->sendargs.sock);
        if (pktxp == NULL) {
            continue;
        }
        if (rtpp_packetport_queue(pvt->ext.in, pktxp) != 0) {
            rtp_packet_ext_dtor(pktxp);
        }
    }
    for (i = 0; i < nwis; i++)
        RTPP_OBJ_DECREF(wis[i]);
    if (term_seen != 0)
        return (-1);
    return (0);
}

static void
rtpp_packetport_drain_queue(struct SPMCQueue *queue)
{
    void *pktxp;

    while (try_pop(queue, &pktxp)) {
        rtp_packet_ext_dtor(pktxp);
    }
}

static void
rtpp_packetport_drain_out(struct rtpp_packetport_int_priv *pvt)
{
    struct rtpp_packet_ext_int *pktxip;
    struct rtpp_refcnt *rco;
    struct rtpp_stream *stp;
    struct rtpp_stream *stp_sendr;
    struct rtp_packet_ext *pktxp;
    struct rtp_packet *pktp;
    struct pkt_proc_ctx pktx;
    size_t i, nitems;

    while ((nitems = try_pop_many(pvt->ext.out, pvt->out_batch,
      (size_t)pvt->capacity)) > 0) {
        for (i = 0; i < nitems; i++) {
            pktxp = pvt->out_batch[i];
            PUB2PVT(pktxp, pktxip);
            pktp = rtpp_packet_ext_get_pkt(pktxp);
            if (pktp == NULL) {
                rtp_packet_ext_dtor(pktxp);
                continue;
            }
            rco = CALL_SMETHOD(pvt->streams_ht, find, &pktxp->port);
            if (rco == NULL) {
                rtp_packet_ext_dtor(pktxp);
                continue;
            }
            stp = CALL_SMETHOD(rco, getdata);
            stp_sendr = CALL_SMETHOD(stp, get_sender);
            pktx = (struct pkt_proc_ctx){
                .strmp_in = stp,
                .strmp_out = stp_sendr,
                .pktp = pktp,
            };
            CALL_SMETHOD(stp->pproc_manager, handle, &pktx);
            if (stp_sendr != NULL) {
                RTPP_OBJ_DECREF(stp_sendr);
            }
            RC_DECREF(rco);
            rtp_packet_ext_dtor(pktxp);
        }
    }
}

static int
rtpp_packetport_ismapped(const void *ptr)
{
    long pagesz;
    uintptr_t page_u;
    char vec;

    pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) {
        return (0);
    }
    page_u = (uintptr_t)ptr - ((uintptr_t)ptr % (uintptr_t)pagesz);
    return (mincore((void *)page_u, (size_t)pagesz, &vec) == 0);
}

static int
rtpp_packetport_nudge(struct rtpp_packetport_int_priv *pvt)
{
    struct rtpp_wi *wi;

    wi = rtpp_wi_malloc_sgnl(RTPP_PPSIG_NUDGE, NULL, 0);
    if (wi == NULL) {
        return (-1);
    }
    if (rtpp_queue_put_item(wi, pvt->pqueue) != 0) {
        RTPP_OBJ_DECREF(wi);
        return (-1);
    }
    return (0);
}

static enum rtpp_ht_key_types
rtpp_packetport_htkey_type(void)
{

    if (sizeof(unsigned int) == sizeof(uint32_t))
        return (rtpp_ht_key_u32_t);
    return (rtpp_ht_key_u64_t);
}

static void
rtpp_packetport_deadline_step(struct timespec *deadline)
{

    deadline->tv_sec += rtpp_packetport_tick.tv_sec;
    deadline->tv_nsec += rtpp_packetport_tick.tv_nsec;
    if (deadline->tv_nsec >= NSEC_MAX) {
        deadline->tv_sec += 1;
        deadline->tv_nsec -= NSEC_MAX;
    }
}

static unsigned int
rtpp_packetport_nport_alloc(_Atomic(unsigned int) *portp)
{
    unsigned int rval;

    rval = atomic_fetch_add_explicit(portp, 2, memory_order_relaxed);
    if (rval == 0) {
        rval = atomic_fetch_add_explicit(portp, 2, memory_order_relaxed);
    }
    return (rval);
}
