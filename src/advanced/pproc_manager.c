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

#include "advanced/pproc_manager.h"
#include "advanced/packet_processor.h"

#define MAX_OBSERVERS 4

struct pproc_manager_pvt {
    struct pproc_manager pub;
    struct packet_processor_if handlers[MAX_OBSERVERS + 1];
};

static int rtpp_pproc_mgr_register(struct pproc_manager *, const struct packet_processor_if *);
static enum pproc_action rtpp_pproc_mgr_handle(struct pproc_manager *, struct pkt_proc_ctx *);

static void
rtpp_pproc_mgr_dtor(struct pproc_manager_pvt *pvt)
{

    free(pvt);
}

struct pproc_manager *
rtpp_pproc_mgr_ctor(void)
{
    struct pproc_manager_pvt *pvt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL)
        return (NULL);
    pvt->pub.reg = rtpp_pproc_mgr_register;
    pvt->pub.handle = rtpp_pproc_mgr_handle;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_pproc_mgr_dtor,
      pvt);
    return (&(pvt->pub));
}

static int
rtpp_pproc_mgr_register(struct pproc_manager *pub, const struct packet_processor_if *ip)
{
    int i;
    struct pproc_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    for (i = 0; i < MAX_OBSERVERS; i++)
        if (pvt->handlers[i].taste == NULL)
            break;
    if (i >= MAX_OBSERVERS)
        return (-1);
    pvt->handlers[i] = *ip;
    return (0);
}

static enum pproc_action
rtpp_pproc_mgr_handle(struct pproc_manager *pub, struct pkt_proc_ctx *pktxp)
{
    int i;
    struct pproc_manager_pvt *pvt;
    enum pproc_action res = PPROC_NOP;

    PUB2PVT(pub, pvt);
    for (i = 0; i < MAX_OBSERVERS; i++) {
        if (pvt->handlers[i].taste == NULL)
            break;
        if (i > 0) {
            /* Clean after use */
            pktxp->auxp = NULL;
        }
        if (pvt->handlers[i].taste(pktxp) == 0)
            continue;
        res |= pvt->handlers[i].enqueue(pvt->handlers[i].arg, pktxp);
        if (res & PPROC_TAKE)
            break;
    }
    return (res);
}
