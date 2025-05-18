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
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtp_packet.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_stats.h"
#include "rtpp_proc.h"
#include "rtpp_codeptr.h"

#include "advanced/pproc_manager.h"
#include "advanced/packet_processor.h"

struct pproc_handler {
    enum pproc_order order;
    struct packet_processor_if ppif;
};

struct pproc_handlers {
    struct rtpp_refcnt *rcnt;
    int nprocs;
    struct pproc_handler pproc[0];
};

struct pproc_manager_pvt {
    struct pproc_manager pub;
    pthread_mutex_t lock;
    struct rtpp_stats *rtpp_stats;
    int npkts_discard_idx;
    struct pproc_handlers *handlers;
};

static int rtpp_pproc_mgr_register(struct pproc_manager *, enum pproc_order, const struct packet_processor_if *);
static enum pproc_action rtpp_pproc_mgr_handle(struct pproc_manager *, struct pkt_proc_ctx *);
static struct pproc_act rtpp_pproc_mgr_handleat(struct pproc_manager *, struct pkt_proc_ctx *,
  enum pproc_order) __attribute__((always_inline));
static int rtpp_pproc_mgr_lookup(struct pproc_manager *, void *, struct packet_processor_if *);
static int rtpp_pproc_mgr_unregister(struct pproc_manager *, void *);
static struct pproc_manager *rtpp_pproc_mgr_clone(struct pproc_manager *);
void rtpp_pproc_mgr_reg_drop(struct pproc_manager *);

DEFINE_SMETHODS(pproc_manager,
    .reg = &rtpp_pproc_mgr_register,
    .handle = &rtpp_pproc_mgr_handle,
    .handleat = &rtpp_pproc_mgr_handleat,
    .lookup = &rtpp_pproc_mgr_lookup,
    .unreg = &rtpp_pproc_mgr_unregister,
    .clone = &rtpp_pproc_mgr_clone,
    .reg_drop = &rtpp_pproc_mgr_reg_drop,
);

static struct pproc_handlers *
pproc_handlers_alloc(int nprocs)
{
    struct pproc_handlers *hndlrs;

    hndlrs = rtpp_rzmalloc(sizeof(*hndlrs) + sizeof(struct pproc_handler) * nprocs,
      offsetof(struct pproc_handlers, rcnt));
    if (hndlrs == NULL)
        return (NULL);
    hndlrs->nprocs = nprocs;
    return (hndlrs);
}

static void
rtpp_pproc_mgr_dtor(struct pproc_manager_pvt *pvt)
{

    RTPP_OBJ_DECREF(pvt->handlers);
}

struct pproc_manager *
pproc_manager_ctor(struct rtpp_stats *rtpp_stats, int nprocs)
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
    RTPP_OBJ_DTOR_ATTACH(&(pvt->pub), pthread_mutex_destroy, &pvt->lock);
    pvt->handlers = pproc_handlers_alloc(nprocs);
    if (pvt->handlers == NULL)
        goto e1;
    RTPP_OBJ_BORROW(&(pvt->pub), rtpp_stats);
    pvt->rtpp_stats = rtpp_stats;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_pproc_mgr_dtor);
    return (&(pvt->pub));
e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static int
rtpp_pproc_mgr_register(struct pproc_manager *pub, enum pproc_order pproc_order,
  const struct packet_processor_if *ip)
{
    int i;
    struct pproc_manager_pvt *pvt;
    struct pproc_handlers *newh;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);

    newh = pproc_handlers_alloc(pvt->handlers->nprocs + 1);
    if (newh == NULL) {
        pthread_mutex_unlock(&pvt->lock);
        return (-1);
    }
    for (i = 0; i < pvt->handlers->nprocs; i++)
        if (pvt->handlers->pproc[i].order > pproc_order)
            break;
    if (i > 0)
        memcpy(&newh->pproc[0], &pvt->handlers->pproc[0],
          sizeof(pvt->handlers->pproc[0]) * i);
    if (i < pvt->handlers->nprocs)
        memcpy(&newh->pproc[i + 1], &pvt->handlers->pproc[i],
          sizeof(pvt->handlers->pproc[0]) * (pvt->handlers->nprocs - i));
    newh->pproc[i].order = pproc_order;
    newh->pproc[i].ppif = *ip;
    for (int j = 0; j < newh->nprocs; j++) {
        ip = &newh->pproc[j].ppif;
        if (ip->rcnt != NULL)
            RTPP_OBJ_BORROW(newh, ip);
    }
    RTPP_OBJ_DECREF(pvt->handlers);
    pvt->handlers = newh;
    pthread_mutex_unlock(&pvt->lock);
    return (0);
}

static enum pproc_action
rtpp_pproc_mgr_handle(struct pproc_manager *pub, struct pkt_proc_ctx *pktxp)
{

    return rtpp_pproc_mgr_handleat(pub, pktxp, _PPROC_ORD_EMPTY).a;
}

static struct pproc_act
rtpp_pproc_mgr_handleat(struct pproc_manager *pub, struct pkt_proc_ctx *pktxp,
  enum pproc_order startat)
{
    int i;
    struct pproc_manager_pvt *pvt;
    enum pproc_action res = PPROC_ACT_NOP_v;
    struct pproc_act lastres = PPROC_ACT(res);
    const struct pproc_handlers *handlers;
    static __thread int max_recursion = 16;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    handlers = pvt->handlers;
    RTPP_OBJ_INCREF(handlers);
    pthread_mutex_unlock(&pvt->lock);

    RTPP_DBGCODE() {
        max_recursion--;
        assert(max_recursion > 0);
    }

    for (i = 0; i < handlers->nprocs; i++) {
        const struct packet_processor_if *ip = &handlers->pproc[i].ppif;
        RTPP_DBG_ASSERT(handlers->pproc[i].order != _PPROC_ORD_EMPTY);
        if (startat > _PPROC_ORD_EMPTY && handlers->pproc[i].order < startat)
            continue;
        if (i > 0) {
            /* Clean after use */
            pktxp->auxp = NULL;
        }
        pktxp->pproc = ip;
        if (ip->taste != NULL && ip->taste(pktxp) == 0)
            continue;
        lastres = ip->enqueue(pktxp);
        res |= lastres.a;
        if (res & (PPROC_ACT_TAKE_v | PPROC_ACT_DROP_v))
            break;
    }
    RTPP_OBJ_DECREF(handlers);
    if ((res & PPROC_ACT_TAKE_v) == 0 || (res & PPROC_ACT_DROP_v) != 0) {
        RTPP_OBJ_DECREF(pktxp->pktp);
        if ((pktxp->flags & PPROC_FLAG_LGEN) == 0) {
            CALL_SMETHOD(pktxp->strmp_in->pcount, reg_drop, lastres.loc);
            if (pktxp->rsp != NULL)
                pktxp->rsp->npkts_discard.cnt++;
            else
                CALL_SMETHOD(pvt->rtpp_stats, updatebyidx, pvt->npkts_discard_idx, 1);
        }
    }
    lastres.a = res;
    RTPP_DBGCODE() {
        max_recursion++;
    }
    return (lastres);
}

int
rtpp_pproc_mgr_lookup(struct pproc_manager *pub, void *key, struct packet_processor_if *rval)
{
    struct pproc_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    for (int i = 0; i < pvt->handlers->nprocs; i++) {
        const struct packet_processor_if *ip = &pvt->handlers->pproc[i].ppif;
        RTPP_DBG_ASSERT(pvt->handlers->pproc[i].order != _PPROC_ORD_EMPTY);
        if (ip->key == key) {
            if (ip->rcnt != NULL)
                RTPP_OBJ_INCREF(ip);
            *rval = *ip;
            pthread_mutex_unlock(&pvt->lock);
            return (1);
        }
    }
    pthread_mutex_unlock(&pvt->lock);
    return (0);
}

static int
rtpp_pproc_mgr_unregister(struct pproc_manager *pub, void *key)
{
    int i;
    struct pproc_manager_pvt *pvt;
    struct pproc_handlers *newh, *oldh;

    PUB2PVT(pub, pvt);
    pthread_mutex_lock(&pvt->lock);
    for (i = 0; i < pvt->handlers->nprocs; i++) {
        const struct packet_processor_if *ip = &pvt->handlers->pproc[i].ppif;
        RTPP_DBG_ASSERT(pvt->handlers->pproc[i].order != _PPROC_ORD_EMPTY);
        if (ip->key != key)
            continue;
        newh = pproc_handlers_alloc(pvt->handlers->nprocs - 1);
        if (newh == NULL) {
            pthread_mutex_unlock(&pvt->lock);
            return (-1);
        }
        if (i > 0)
            memcpy(&newh->pproc[0], &pvt->handlers->pproc[0],
              sizeof(pvt->handlers->pproc[0]) * i);
        if (i < pvt->handlers->nprocs - 1)
            memcpy(&newh->pproc[i], &pvt->handlers->pproc[i + 1],
              sizeof(pvt->handlers->pproc[0]) * (pvt->handlers->nprocs - i - 1));
        for (int j = 0; j < newh->nprocs; j++) {
            ip = &newh->pproc[j].ppif;
            if (ip->rcnt != NULL)
                RTPP_OBJ_BORROW(newh, ip);
        }
        oldh = pvt->handlers;
        pvt->handlers = newh;
        pthread_mutex_unlock(&pvt->lock);
        /* DECREF might call a destructor chain, so it should be done out */
        /* of the locked area! */
        RTPP_OBJ_DECREF(oldh);
        return (0);
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
    pthread_mutex_lock(&pvt->lock);
    rval = pproc_manager_ctor(pvt->rtpp_stats, pvt->handlers->nprocs);
    if (rval == NULL) {
        pthread_mutex_unlock(&pvt->lock);
        return (NULL);
    }
    PUB2PVT(rval, pvt_new);
    memcpy(pvt_new->handlers->pproc, pvt->handlers->pproc,
      sizeof(pvt->handlers->pproc[0]) * pvt->handlers->nprocs);
    for (i = 0; i < pvt->handlers->nprocs; i++) {
        const struct packet_processor_if *ip = &pvt_new->handlers->pproc[i].ppif;
        RTPP_DBG_ASSERT(pvt->handlers->pproc[i].order != _PPROC_ORD_EMPTY);
        if (ip->rcnt != NULL)
            RTPP_OBJ_BORROW(pvt->handlers, ip);
    }
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

void
rtpp_pproc_mgr_reg_drop(struct pproc_manager *pub)
{
    struct pproc_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    CALL_SMETHOD(pvt->rtpp_stats, updatebyidx, pvt->npkts_discard_idx, 1);
}
