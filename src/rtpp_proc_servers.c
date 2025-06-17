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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_hash_table.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_proc.h"
#include "rtpp_proc_servers.h"
#include "rtpp_proc_servers_fin.h"
#include "rtpp_server.h"
#include "rtpp_stream.h"
#include "rtpp_refcnt.h"
#include "rtpp_netio_async.h"
#include "rtpp_mallocs.h"
#include "rtpp_stats.h"
#include "rtpp_debug.h"
#include "rtpp_queue.h"
#include "rtpp_wi.h"
#include "rtpp_wi_sgnl.h"
#include "rtpp_wi_data.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

struct rtpp_proc_servers_priv {
    struct rtpp_proc_servers pub;
    struct rtpp_anetio_cf *netio;
    const struct rtpp_cfg *cfsp;
    struct rtpp_proc_stat npkts_played;
    pthread_t thread_id;
    struct rtpp_queue *cmd_q;
    struct rtpp_wi *sigterm;
    struct rtpp_weakref *act_servers;
    struct rtpp_weakref *inact_servers;
};

static int rtpp_proc_servers_reg(struct rtpp_proc_servers *,
  struct rtpp_server *, int);
static int rtpp_proc_servers_unreg(struct rtpp_proc_servers *, uint64_t);
static int rtpp_proc_servers_plr_start(struct rtpp_proc_servers *, uint64_t, double);

DEFINE_SMETHODS(rtpp_proc_servers,
    .reg = &rtpp_proc_servers_reg,
    .unreg = &rtpp_proc_servers_unreg,
    .plr_start = &rtpp_proc_servers_plr_start,
);

struct foreach_args {
    double dtime;
    struct sthread_args *sender;
    struct rtpp_proc_stat *npkts_played;
    const struct rtpp_cfg *cfsp;
    struct rtpp_weakref *inact_servers;
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
    strmp_out = CALL_SMETHOD(fap->cfsp->rtp_streams_wrt, get_by_idx, rsrv->stuid);
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
          PPROC_ORD_PLAY + 1).a & PPROC_ACT_TAKE_v)
            fap->npkts_played->cnt++;
    }
    RTPP_OBJ_DECREF(strmp_in);
e1:
    RTPP_OBJ_DECREF(strmp_out);
e0:
    return (RTPP_WR_MATCH_CONT);
}


static void
run_servers(struct rtpp_proc_servers_priv *tp, double dtime)
{
    const struct foreach_args fargs = {
        .dtime = dtime,
        .sender = rtpp_anetio_pick_sender(tp->netio),
        .npkts_played = &tp->npkts_played,
        .cfsp = tp->cfsp,
        .inact_servers = tp->inact_servers,
    };

    CALL_SMETHOD(tp->act_servers, foreach, process_rtp_servers_foreach,
      (void *)&fargs);

    rtpp_anetio_pump_q(fargs.sender);
    FLUSH_STAT(tp->cfsp->rtpp_stats, tp->npkts_played);
}

static void
rtpp_proc_servers_run(void *argp)
{
    struct rtpp_proc_servers_priv *stap;
    struct rtpp_wi *wi;
    int signum, rval;
    double next_dtime = 0;
    struct timespec deadline;

    stap = (struct rtpp_proc_servers_priv *)argp;
    for (;;) {
        if (CALL_SMETHOD(stap->act_servers, get_length) == 0) {
            wi = rtpp_queue_get_item(stap->cmd_q, 1);
            next_dtime = 0;
            if (wi == NULL)
                continue;
        } else {
            if (next_dtime != 0) {
                dtime2mtimespec(next_dtime, &deadline);
                rval = 0;
                wi = rtpp_queue_get_item_by(stap->cmd_q, &deadline, &rval);
            } else {
                wi = NULL;
                rval = ETIMEDOUT;
                next_dtime = getdtime();
            }
            if (wi == NULL) {
                if (rval == ETIMEDOUT) {
                    run_servers(stap, next_dtime);
                    next_dtime += 0.01;
                }
                continue;
            }
        }
        switch (wi->wi_type) {
        case RTPP_WI_TYPE_SGNL:
            signum = rtpp_wi_sgnl_get_signum(wi);
            RTPP_OBJ_DECREF(wi);
            if (signum == SIGTERM) {
                goto exit;
            }
            abort();

        default:
            abort();
        }
        RTPP_OBJ_DECREF(wi);
    }
exit:
    /* We are terminating, get rid of all requests */
    return;
}

static void
rtpp_proc_servers_dtor(struct rtpp_proc_servers_priv *stap)
{

    rtpp_proc_servers_fin(&(stap->pub));
    rtpp_queue_put_item(stap->sigterm, stap->cmd_q);
    pthread_join(stap->thread_id, NULL);
    rtpp_queue_destroy(stap->cmd_q);
}

struct rtpp_proc_servers *
rtpp_proc_servers_ctor(const struct rtpp_cfg *cfsp, struct rtpp_anetio_cf *netio)
{
    struct rtpp_proc_servers_priv *stap;

    stap = rtpp_rzmalloc(sizeof(*stap), PVT_RCOFFS(stap));
    if (stap == NULL)
        goto e0;
    stap->cmd_q = rtpp_queue_init(RTPQ_TINY_CB_LEN, "rtpp_proc_servers(requests)");
    if (stap->cmd_q == NULL) {
        goto e1;
    }
    stap->sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (stap->sigterm == NULL) {
        goto e2;
    }
    stap->act_servers = rtpp_weakref_ctor();
    if (stap->act_servers == NULL) {
        goto e3;
    }
    RTPP_OBJ_DTOR_ATTACH_OBJ(&stap->pub, stap->act_servers);
    stap->inact_servers = rtpp_weakref_ctor();
    if (stap->inact_servers == NULL) {
        goto e3;
    }
    RTPP_OBJ_DTOR_ATTACH_OBJ(&stap->pub, stap->inact_servers);

    stap->inact_servers->ht->seed = stap->act_servers->ht->seed;
    stap->netio = netio;
    stap->cfsp = cfsp;
    stap->npkts_played.cnt_idx = CALL_SMETHOD(cfsp->rtpp_stats, getidxbyname, "npkts_played");

    if (pthread_create(&stap->thread_id, NULL,
      (void *(*)(void *))&rtpp_proc_servers_run, stap) != 0) {
        goto e3;
    }
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(stap->thread_id, "rtpp_proc_servers");
#endif

    PUBINST_FININIT(&stap->pub, stap, rtpp_proc_servers_dtor);
    return (&stap->pub);
e3:
    RTPP_OBJ_DECREF(stap->sigterm);
e2:
    rtpp_queue_destroy(stap->cmd_q);
e1:
    RTPP_OBJ_DECREF(&stap->pub);
e0:
    return (NULL);
}

static int
rtpp_proc_servers_reg(struct rtpp_proc_servers *self,
  struct rtpp_server *rsrv, int inact)
{
    struct rtpp_proc_servers_priv *stap;

    PUB2PVT(self, stap);

    if (inact) {
        if (CALL_SMETHOD(stap->inact_servers, reg, rsrv->rcnt, rsrv->sruid) != 0)
            return (-1);
    } else {
        if (CALL_SMETHOD(stap->act_servers, reg, rsrv->rcnt, rsrv->sruid) != 0)
            return (-1);
        rtpp_queue_wakeup(stap->cmd_q);
    }
    return (0);
}

static int
rtpp_proc_servers_plr_start(struct rtpp_proc_servers *self, uint64_t sruid, double dtime)
{
    struct rtpp_proc_servers_priv *stap;
    struct rtpp_refcnt *rco;
    struct rtpp_server *rsrv;

    PUB2PVT(self, stap);
    rco = CALL_SMETHOD(stap->inact_servers, move, sruid, stap->act_servers);
    RTPP_DBG_ASSERT(rco != NULL);
    if (rco == NULL) {
        return (-1);
    }
    rsrv = CALL_SMETHOD(rco, getdata);
    CALL_SMETHOD(rsrv, start, dtime);
    RTPP_OBJ_DECREF(rsrv);
    rtpp_queue_wakeup(stap->cmd_q);
    return (0);
}

static int
rtpp_proc_servers_unreg(struct rtpp_proc_servers *self, uint64_t sruid)
{
    struct rtpp_proc_servers_priv *stap;
    struct rtpp_refcnt *rco;

    PUB2PVT(self, stap);
    rco = CALL_SMETHOD(stap->inact_servers, unreg, sruid);
    if (rco == NULL)
        rco = CALL_SMETHOD(stap->act_servers, unreg, sruid);
    RTPP_DBG_ASSERT(rco != NULL);
    return (rco != NULL ? 0 : -1);
}
