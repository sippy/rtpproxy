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

#include <stddef.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"

#include "advanced/po_manager.h"
#include "advanced/packet_observer.h"

#define MAX_OBSERVERS 4

struct po_manager_pvt {
    struct po_manager pub;
    struct packet_observer_if observers[MAX_OBSERVERS + 1];
};

static int rtpp_po_mgr_register(struct po_manager *, const struct packet_observer_if *);
static int rtpp_po_mgr_observe(struct po_manager *, struct po_mgr_pkt_ctx *);

static void
rtpp_po_mgr_dtor(struct po_manager_pvt *pvt)
{

    free(pvt);
}

struct po_manager *
rtpp_po_mgr_ctor(void)
{
    struct po_manager_pvt *pvt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL)
        return (NULL);
    pvt->pub.reg = rtpp_po_mgr_register;
    pvt->pub.observe = rtpp_po_mgr_observe;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_po_mgr_dtor,
      pvt);
    return (&(pvt->pub));
}

static int
rtpp_po_mgr_register(struct po_manager *pub, const struct packet_observer_if *ip)
{
    int i;
    struct po_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    for (i = 0; i < MAX_OBSERVERS; i++)
        if (pvt->observers[i].taste == NULL)
            break;
    if (i >= MAX_OBSERVERS)
        return (-1);
    pvt->observers[i] = *ip;
    return (0);
}

static int
rtpp_po_mgr_observe(struct po_manager *pub, struct po_mgr_pkt_ctx *pktxp)
{
    struct po_manager_pvt *pvt;
    int rval = POM_NOP;

    PUB2PVT(pub, pvt);
    for (pktxp->lastpoidx = 0; pktxp->lastpoidx < MAX_OBSERVERS; pktxp->lastpoidx++) {
        if (pvt->observers[pktxp->lastpoidx].taste == NULL)
            break;
        if (pktxp->lastpoidx > 0) {
            /* Clean after use */
            pktxp->auxp = NULL;
        }
        if (pvt->observers[pktxp->lastpoidx].taste(pktxp) == 0)
            continue;
        switch (pvt->observers[pktxp->lastpoidx].enqueue(pvt->observers[pktxp->lastpoidx].arg,
          pktxp)) {
        case POM_CONSUME:
            return (POM_CONSUME);
        case POM_COPY:
            rval = POM_COPY;
        default:
            break;
        }
    }
    return (rval);
}
