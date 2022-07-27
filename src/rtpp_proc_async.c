/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <elperiodic.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_weakref.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_async.h"
#include "rtpp_debug.h"
#include "rtpp_netio_async.h"
#include "rtpp_proc.h"
#include "rtpp_proc_async.h"
#include "rtpp_proc_servers.h"
#include "rtpp_mallocs.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_pipe.h"

struct elp_data {
    void *obj;
    long long ncycles_ref;
    long long ncycles_ref_last;
    long long ncycles_chk_ol;
    double target_pfreq;
};

struct rtpp_proc_async_cf;

struct rtpp_proc_thread_cf {
    pthread_t thread_id;
    atomic_int tstate;
    struct elp_data elp_fs;
    struct elp_data elp_lz;
    int pipe_type;
    const struct rtpp_proc_async_cf *proc_cf;
    struct rtpp_proc_rstats *rsp;
};

struct rtpp_proc_async_cf {
    struct rtpp_proc_async pub;
    struct rtpp_proc_rstats rstats;
    const struct rtpp_cfg *cf_save;
    struct rtpp_proc_thread_cf rtp_thread;
    struct rtpp_proc_thread_cf rtcp_thread;
};

#define TSTATE_RUN   0x0
#define TSTATE_CEASE 0x1

static void rtpp_proc_async_dtor(struct rtpp_proc_async *);

#define FLUSH_STAT(sobj, st)	{ \
    if ((st).cnt > 0) { \
        CALL_SMETHOD(sobj, updatebyidx, (st).cnt_idx, (st).cnt); \
        (st).cnt = 0; \
    } \
}

static void
flush_rstats(struct rtpp_stats *sobj, struct rtpp_proc_rstats *rsp)
{

    FLUSH_STAT(sobj, rsp->npkts_rcvd);
    FLUSH_STAT(sobj, rsp->npkts_played);
    FLUSH_STAT(sobj, rsp->npkts_relayed);
    FLUSH_STAT(sobj, rsp->npkts_resizer_in);
    FLUSH_STAT(sobj, rsp->npkts_resizer_out);
    FLUSH_STAT(sobj, rsp->npkts_resizer_discard);
    FLUSH_STAT(sobj, rsp->npkts_discard);
}

static void
init_rstats(struct rtpp_stats *sobj, struct rtpp_proc_rstats *rsp)
{

    rsp->npkts_rcvd.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_rcvd");
    rsp->npkts_played.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_played");
    rsp->npkts_relayed.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_relayed");
    rsp->npkts_resizer_in.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_in");
    rsp->npkts_resizer_out.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_out");
    rsp->npkts_resizer_discard.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_resizer_discard");
    rsp->npkts_discard.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "npkts_discard");
}

static void
rtpp_proc_async_run(void *arg)
{
    const struct rtpp_cfg *cfsp;
    int ndrain;
    int nready;
    struct rtpp_proc_thread_cf *tcp;
    const struct rtpp_proc_async_cf *proc_cf;
    long long last_ctick;
    struct sthread_args *sender;
    struct rtpp_proc_rstats *rstats;
    struct rtpp_stats *stats_cf;
    struct rtpp_polltbl ptbl;
    int tstate, overload;
    struct rtpp_timestamp rtime;
    struct elp_data *edp;

    tcp = (struct rtpp_proc_thread_cf *)arg;
    proc_cf = tcp->proc_cf;
    cfsp = proc_cf->cf_save;
    stats_cf = cfsp->rtpp_stats;
    rstats = tcp->rsp;

    memset(&ptbl, '\0', sizeof(struct rtpp_polltbl));

    memset(&rtime, '\0', sizeof(rtime));

    RTPP_DBGCODE(netio) {
        last_ctick = 0;
    }
    overload = 0;

    edp = &tcp->elp_lz;

    for (;;) {
        tstate = atomic_load(&tcp->tstate);
        if (tstate == TSTATE_CEASE) {
            break;
        }
        edp->ncycles_ref = (long long)prdic_getncycles_ref(edp->obj);
        if (cfsp->overload_prot.ecode != 0 && edp->ncycles_chk_ol <= edp->ncycles_ref) {
            double lv = prdic_getload(edp->obj);

            if (overload  && lv < 0.85) {
                overload = 0;
                CALL_METHOD(cfsp->rtpp_cmd_cf, reg_overload, 0);
            } else if (overload == 0 && lv > 0.9) {
                overload = 1;
                CALL_METHOD(cfsp->rtpp_cmd_cf, reg_overload, 1);
            }
            RTPP_LOG(cfsp->glog, RTPP_LOG_INFO, "ncycles=%lld load=%f",
              edp->ncycles_ref, lv);
            edp->ncycles_chk_ol = ((edp->ncycles_ref / 200) + 1) * 200;
        }
        ndrain = ((edp->ncycles_ref - edp->ncycles_ref_last) * MAX_RTP_RATE) / edp->target_pfreq;
        edp->ncycles_ref_last = edp->ncycles_ref;

        if (ndrain < 1) {
            ndrain = 1;
        }

        CALL_METHOD(cfsp->sessinfo, sync_polltbl, &ptbl, tcp->pipe_type);
        nready = 0;
        if (ptbl.curlen > 0) {
            RTPP_DBGCODE(netio > 1) {
                RTPP_LOG(cfsp->glog, RTPP_LOG_DBUG, "run %lld " \
                  "polling for %d %s file descriptors", \
                  last_ctick, ptbl.curlen, PP_NAME(tcp->pipe_type));
            }
            nready = poll(ptbl.pfds, ptbl.curlen, 0);
            RTPP_DBGCODE(netio) {
                RTPP_DBGCODE(netio > 1 || nready > 0) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_DBUG, "run %lld " \
                      "polling for %d %s file descriptors: %d descriptors are ready", \
                      last_ctick, ptbl.curlen, PP_NAME(tcp->pipe_type), nready);
                }
            }
            if (nready < 0 && errno == EINTR) {
                continue;
            }
        }

        rtpp_timestamp_get(&rtime);
        RTPP_DBG_ASSERT(rtime.wall > 0 && rtime.mono > 0);

        sender = rtpp_anetio_pick_sender(proc_cf->pub.netio);
        if (nready > 0) {
            process_rtp_only(cfsp, &ptbl, &rtime, ndrain, sender, rstats);
        }

        if (tcp->pipe_type == PIPE_RTP && CALL_METHOD(cfsp->servers_wrt, get_length) > 0) {
            rtpp_proc_servers(cfsp, rtime.mono, sender, rstats);
        }

        rtpp_anetio_pump_q(sender);
        flush_rstats(stats_cf, rstats);

        if (ptbl.curlen > 0) {
            if (edp == &tcp->elp_lz) {
                edp = &tcp->elp_fs;
            }
        } else {
            if (edp == &tcp->elp_fs) {
                edp = &tcp->elp_lz;
            }
        }
        prdic_procrastinate(edp->obj);
        RTPP_DBGCODE(netio) {
            last_ctick++;
        }
    }
    rtpp_polltbl_free(&ptbl);
}

static int
rtpp_proc_async_thread_init(const struct rtpp_cfg *cfsp, const struct rtpp_proc_async_cf *proc_cf,
  struct rtpp_proc_thread_cf *tcp, int pipe_type)
{

    tcp->elp_fs.obj = prdic_init(cfsp->target_pfreq, 0.0);
    if (tcp->elp_fs.obj == NULL) {
        goto e1;
    }
    tcp->elp_fs.target_pfreq = cfsp->target_pfreq;
    tcp->elp_lz.obj = prdic_init(10.0, 0.0);
    if (tcp->elp_lz.obj == NULL) {
        goto e2;
    }
    tcp->elp_lz.target_pfreq = 10.0;

    tcp->proc_cf = proc_cf;
    tcp->pipe_type = pipe_type;

    if (pthread_create(&tcp->thread_id, NULL, (void *(*)(void *))&rtpp_proc_async_run, tcp) != 0) {
        goto e3;
    }
    return (0);

e3:
    prdic_free(tcp->elp_lz.obj);
e2:
    prdic_free(tcp->elp_fs.obj);
e1:
    return (-1);
}

static void
rtpp_proc_async_thread_destroy(struct rtpp_proc_thread_cf *tcp)
{
    int tstate = atomic_load(&tcp->tstate);

    assert(tstate == TSTATE_RUN);
    atomic_store(&tcp->tstate, TSTATE_CEASE);
    pthread_join(tcp->thread_id, NULL);
    prdic_free(tcp->elp_lz.obj);
    prdic_free(tcp->elp_fs.obj);
}

struct rtpp_proc_async *
rtpp_proc_async_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = rtpp_zmalloc(sizeof(*proc_cf));
    if (proc_cf == NULL)
        return (NULL);

    init_rstats(cfsp->rtpp_stats, &proc_cf->rstats);
    proc_cf->rtp_thread.rsp = proc_cf->rtcp_thread.rsp = &proc_cf->rstats;

    proc_cf->pub.netio = rtpp_netio_async_init(cfsp, 1);
    if (proc_cf->pub.netio == NULL) {
        goto e0;
    }

    proc_cf->cf_save = cfsp;

    if (rtpp_proc_async_thread_init(cfsp, proc_cf, &proc_cf->rtp_thread, PIPE_RTP) != 0) {
        goto e1;
    }

    if (rtpp_proc_async_thread_init(cfsp, proc_cf, &proc_cf->rtcp_thread, PIPE_RTCP) != 0) {
        goto e2;
    }

    proc_cf->pub.dtor = &rtpp_proc_async_dtor;
    return (&proc_cf->pub);
e2:
    rtpp_proc_async_thread_destroy(&proc_cf->rtp_thread);
e1:
    rtpp_netio_async_destroy(proc_cf->pub.netio);
e0:
    free(proc_cf);
    return (NULL);
}

static void
rtpp_proc_async_dtor(struct rtpp_proc_async *pub)
{
    struct rtpp_proc_async_cf *proc_cf;

    PUB2PVT(pub, proc_cf);
    rtpp_proc_async_thread_destroy(&proc_cf->rtcp_thread);
    rtpp_proc_async_thread_destroy(&proc_cf->rtp_thread);
    rtpp_netio_async_destroy(proc_cf->pub.netio);
    free(proc_cf);
}
