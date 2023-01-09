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

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtp_packet.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_stats.h"
#include "rtpp_proc.h"

#include "advanced/pproc_manager.h"
#include "advanced/packet_processor.h"

#define MAX_PKT_PROCS 8

struct pproc_manager_pvt {
    struct pproc_manager pub;
    pthread_mutex_t lock;
    struct rtpp_stats *rtpp_stats;
    int npkts_discard_idx;
    struct {
        enum pproc_order pproc_order;
        struct packet_processor_if pproc_if;
    } handlers[MAX_PKT_PROCS + 1];
};

static int rtpp_pproc_mgr_register(struct pproc_manager *, enum pproc_order, const struct packet_processor_if *);
static enum pproc_action rtpp_pproc_mgr_handle(struct pproc_manager *, struct pkt_proc_ctx *);
static enum pproc_action rtpp_pproc_mgr_handleat(struct pproc_manager *, struct pkt_proc_ctx *,
  enum pproc_order) __attribute__((always_inline));
static const struct packet_processor_if *rtpp_pproc_mgr_lookup(struct pproc_manager *,
  void *);
static void rtpp_pproc_mgr_unregister(struct pproc_manager *, void *);
static struct pproc_manager *rtpp_pproc_mgr_clone(struct pproc_manager *);

static const struct pproc_manager_smethods _rtpp_pproc_mgr_smethods = {
    .reg = &rtpp_pproc_mgr_register,
    .handle = &rtpp_pproc_mgr_handle,
    .handleat = &rtpp_pproc_mgr_handleat,
    .lookup = &rtpp_pproc_mgr_lookup,
    .unreg = &rtpp_pproc_mgr_unregister,
    .clone = &rtpp_pproc_mgr_clone
};
const struct pproc_manager_smethods * const pproc_manager_smethods = &_rtpp_pproc_mgr_smethods;

static void
rtpp_pproc_mgr_dtor(struct pproc_manager_pvt *pvt)
{
    int i;

    for (i = 0; i < MAX_PKT_PROCS; i++) {
        const struct packet_processor_if *ip = &pvt->handlers[i].pproc_if;
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY)
            break;
        if (ip->rcnt != NULL)
            RTPP_OBJ_DECREF(ip);
    }
    pthread_mutex_destroy(&pvt->lock);
    RTPP_OBJ_DECREF(pvt->rtpp_stats);
    free(pvt);
}

struct pproc_manager *
rtpp_pproc_mgr_ctor(struct rtpp_stats *rtpp_stats)
{
    struct pproc_manager_pvt *pvt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL)
        goto e0;
    pvt->npkts_discard_idx = CALL_SMETHOD(rtpp_stats, getidxbyname, "npkts_discard");
    if (pvt->npkts_discard_idx < 0)
        goto e1;
    if (pthread_mutex_init(&pvt->lock, NULL) != 0)
        goto e1;
    RTPP_OBJ_INCREF(rtpp_stats);
    pvt->rtpp_stats = rtpp_stats;
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = pproc_manager_smethods;
#endif
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pproc_mgr_dtor,
      pvt);
    return (&(pvt->pub));
e1:
    free(pvt);
e0:
    return (NULL);
}

static int
rtpp_pproc_mgr_register(struct pproc_manager *pub, enum pproc_order pproc_order,
  const struct packet_processor_if *ip)
{
    int i;
    struct pproc_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->handlers[MAX_PKT_PROCS - 1].pproc_order != _PPROC_ORD_EMPTY) {
        pthread_mutex_unlock(&pvt->lock);
        return (-1);
    }
    for (i = 0; i < MAX_PKT_PROCS; i++)
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY || pvt->handlers[i].pproc_order > pproc_order)
            break;
    RTPP_DBG_ASSERT(i < MAX_PKT_PROCS);
    if (pvt->handlers[i].pproc_order != _PPROC_ORD_EMPTY)
        memmove(&pvt->handlers[i + 1], &pvt->handlers[i], sizeof(pvt->handlers[0]) * (MAX_PKT_PROCS - i - 1));
    pvt->handlers[i].pproc_order = pproc_order;
    pvt->handlers[i].pproc_if = *ip;
    if (ip->rcnt != NULL)
        RTPP_OBJ_INCREF(ip);
    pthread_mutex_unlock(&pvt->lock);
    return (0);
}

static enum pproc_action
rtpp_pproc_mgr_handle(struct pproc_manager *pub, struct pkt_proc_ctx *pktxp)
{

    return rtpp_pproc_mgr_handleat(pub, pktxp, _PPROC_ORD_EMPTY);
}

static enum pproc_action
rtpp_pproc_mgr_handleat(struct pproc_manager *pub, struct pkt_proc_ctx *pktxp,
  enum pproc_order startat)
{
    int i;
    struct pproc_manager_pvt *pvt;
    enum pproc_action res = PPROC_ACT_NOP;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    for (i = 0; i < MAX_PKT_PROCS; i++) {
        const struct packet_processor_if *ip = &pvt->handlers[i].pproc_if;
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY)
            break;
        if (startat > _PPROC_ORD_EMPTY && pvt->handlers[i].pproc_order < startat)
            continue;
        if (i > 0) {
            /* Clean after use */
            pktxp->auxp = NULL;
        }
        pktxp->pproc = ip;
        if (ip->taste != NULL && ip->taste(pktxp) == 0)
            continue;
        res |= ip->enqueue(pktxp);
        if (res & (PPROC_ACT_TAKE | PPROC_ACT_DROP))
            break;
    }
    pthread_mutex_unlock(&pvt->lock);
    if ((res & PPROC_ACT_TAKE) == 0 || (res & PPROC_ACT_DROP) != 0) {
        RTPP_OBJ_DECREF(pktxp->pktp);
        CALL_SMETHOD(pktxp->strmp_in->pcount, reg_drop);
        if (pktxp->rsp != NULL)
            pktxp->rsp->npkts_discard.cnt++;
        else
            CALL_SMETHOD(pvt->rtpp_stats, updatebyidx, pvt->npkts_discard_idx, 1);
    }
    return (res);
}

static const struct packet_processor_if *
rtpp_pproc_mgr_lookup(struct pproc_manager *pub, void *key)
{
    struct pproc_manager_pvt *pvt;
    const struct packet_processor_if *rval;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    for (int i = 0; i < MAX_PKT_PROCS; i++) {
        rval = &pvt->handlers[i].pproc_if;
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY)
            goto out;
        if (rval->key == key) {
            pthread_mutex_unlock(&pvt->lock);
            return (rval);
        }
    }
out:
    pthread_mutex_unlock(&pvt->lock);
    return (NULL);
}

static void
rtpp_pproc_mgr_unregister(struct pproc_manager *pub, void *key)
{
    int i;
    struct pproc_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    for (i = 0; i < MAX_PKT_PROCS; i++) {
        const struct packet_processor_if *ip = &pvt->handlers[i].pproc_if;
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY)
            break;
        if (ip->key != key)
            continue;
        if (ip->rcnt != NULL)
            RTPP_OBJ_DECREF(ip);
        if (i < MAX_PKT_PROCS - 1)
            memmove(&pvt->handlers[i], &pvt->handlers[i + 1],
              sizeof(pvt->handlers[0]) * (MAX_PKT_PROCS - i - 1));
        memset(&pvt->handlers[MAX_PKT_PROCS - 1], '\0', sizeof(pvt->handlers[0]));
        pthread_mutex_unlock(&pvt->lock);
        return;
    }
    abort();
}

static struct pproc_manager *
rtpp_pproc_mgr_clone(struct pproc_manager *pub)
{
    struct pproc_manager *rval;
    struct pproc_manager_pvt *pvt, *pvt_new;
    int i;

    PUB2PVT(pub, pvt);
    rval = rtpp_pproc_mgr_ctor(pvt->rtpp_stats);
    if (rval == NULL)
        return (NULL);
    PUB2PVT(rval, pvt_new);
    pthread_mutex_lock(&pvt->lock);
    memcpy(pvt_new->handlers, pvt->handlers, sizeof(pvt->handlers));
    pthread_mutex_unlock(&pvt->lock);
    for (i = 0; i < MAX_PKT_PROCS; i++) {
        const struct packet_processor_if *ip = &pvt_new->handlers[i].pproc_if;
        if (pvt->handlers[i].pproc_order == _PPROC_ORD_EMPTY)
            break;
        if (ip->rcnt != NULL)
            RTPP_OBJ_INCREF(ip);
    }
    return (rval);
}
