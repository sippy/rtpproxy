/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_hash_table.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_proc.h"
#include "rtpp_proc_servers.h"
#include "rtpp_server.h"
#include "rtpp_stream.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_refcnt.h"
#include "rtpp_netio_async.h"
#include "rtpp_mallocs.h"
#include "rtpp_stats.h"
#include "rtpp_debug.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

struct rtpp_proc_servers_priv {
    struct rtpp_proc_servers pub;
    struct rtpp_anetio_cf *netio;
    const struct rtpp_cfg *cfsp;
    struct rtpp_timed_task *ttp;
    struct rtpp_proc_stat npkts_played;
};

struct foreach_args {
    double dtime;
    struct sthread_args *sender;
    struct rtpp_proc_stat *npkts_played;
    const struct rtpp_cfg *cfsp;
};

static int
process_rtp_servers_foreach(void *dp, void *ap)
{
    const struct foreach_args *fap;
    struct rtpp_server *rsrv;
    struct rtp_packet *pkt;
    int len;
    struct rtpp_stream *strmp_out;
    struct rtpp_stream *strmp_in;

    fap = (struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    rsrv = (struct rtpp_server *)dp;
    strmp_out = CALL_METHOD(fap->cfsp->rtp_streams_wrt, get_by_idx, rsrv->stuid);
    if (strmp_out == NULL)
        goto e0;
    strmp_in = CALL_SMETHOD(strmp_out, get_sender, fap->cfsp);
    if (strmp_in == NULL)
        goto e1;
    for (;;) {
        pkt = CALL_SMETHOD(rsrv, get, fap->dtime, &len);
        if (pkt == NULL) {
            if (len == RTPS_EOF) {
                CALL_SMETHOD(strmp_out, finish_playback, rsrv->sruid);
                RTPP_OBJ_DECREF(strmp_in);
                RTPP_OBJ_DECREF(strmp_out);
                return (RTPP_WR_MATCH_DEL);
            } else if (len != RTPS_LATER) {
                /* XXX some error, brag to logs */
            }
            break;
        }
        pkt->sender = fap->sender;
        struct pkt_proc_ctx pktx = {
            .strmp_in = strmp_in,
            .strmp_out = strmp_out,
            .pktp = pkt,
            .flags = PPROC_FLAG_LGEN,
        };
        if (CALL_SMETHOD(strmp_in->pproc_manager, handleat, &pktx,
          PPROC_ORD_PLAY + 1) & PPROC_ACT_TAKE)
            fap->npkts_played->cnt++;
    }
    RTPP_OBJ_DECREF(strmp_in);
e1:
    RTPP_OBJ_DECREF(strmp_out);
e0:
    return (RTPP_WR_MATCH_CONT);
}


static enum rtpp_timed_cb_rvals
run_servers(double dtime, void *arg)
{
    struct rtpp_proc_servers_priv *tp = arg;
    const struct foreach_args fargs = {
        .dtime = dtime,
        .sender = rtpp_anetio_pick_sender(tp->netio),
        .npkts_played = &tp->npkts_played,
        .cfsp = tp->cfsp,
    };

    CALL_METHOD(tp->cfsp->servers_wrt, foreach, process_rtp_servers_foreach,
      (void *)&fargs);

    rtpp_anetio_pump_q(fargs.sender);
    FLUSH_STAT(tp->cfsp->rtpp_stats, tp->npkts_played);

    return CB_MORE;
}

static void
first_server(void *arg)
{
    struct rtpp_proc_servers_priv *tp = arg;

    RTPP_DBG_ASSERT(tp->ttp == NULL);

    tp->ttp = CALL_SMETHOD(tp->cfsp->rtpp_timed_cf, schedule_rc, 0.01, \
      tp->pub.rcnt, run_servers, NULL, arg);
}

static void
last_server(void *arg)
{
    struct rtpp_proc_servers_priv *tp = arg;

    RTPP_DBG_ASSERT(tp->ttp != NULL);

    CALL_METHOD(tp->ttp, cancel);
    RTPP_OBJ_DECREF(tp->ttp);
    tp->ttp = NULL;
}

static void
rtpp_proc_servers_dtor(struct rtpp_proc_servers_priv *stap)
{
    CALL_METHOD(stap->cfsp->servers_wrt, set_on_first, NULL, NULL);
    CALL_METHOD(stap->cfsp->servers_wrt, set_on_last, NULL, NULL);
    free(stap);
}

struct rtpp_proc_servers *
rtpp_proc_servers_ctor(const struct rtpp_cfg *cfsp, struct rtpp_anetio_cf *netio)
{
    struct rtpp_proc_servers_priv *stap;

    stap = rtpp_rzmalloc(sizeof(*stap), PVT_RCOFFS(stap));
    if (stap == NULL)
        goto e0;

    stap->netio = netio;
    stap->cfsp = cfsp;
    stap->npkts_played.cnt_idx = CALL_SMETHOD(cfsp->rtpp_stats, getidxbyname, "npkts_played");

    CALL_METHOD(cfsp->servers_wrt, set_on_first, first_server, stap);
    CALL_METHOD(cfsp->servers_wrt, set_on_last, last_server, stap);

    CALL_SMETHOD(stap->pub.rcnt, attach, (rtpp_refcnt_dtor_t)rtpp_proc_servers_dtor, stap);
    return (&stap->pub);
e0:
    return (NULL);
}
