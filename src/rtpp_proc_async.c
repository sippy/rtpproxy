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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
#include "rtpp_proc_wakeup.h"
#include "rtpp_mallocs.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_pipe.h"
#include "rtpp_epoll.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_debug.h"
#include "rtpp_stream.h"
#include "rtpp_record.h"
#include "rtpp_pcount.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_ttl.h"
#include "rtpp_threads.h"
#include "advanced/pproc_manager.h"
#include "advanced/packet_processor.h"

struct rtpp_proc_async_cf;

struct rtpp_proc_thread_cf {
    pthread_t thread_id;
    _Atomic(int) tstate;
    int pipe_type;
    struct rtpp_polltbl ptbl;
    const struct rtpp_proc_async_cf *proc_cf;
    struct rtpp_proc_rstats rstats;
    struct epoll_event *events;
    int events_alloc;
};

struct rtpp_proc_async_cf {
    struct rtpp_proc_async pub;
    const struct rtpp_cfg *cf_save;
    struct rtpp_proc_thread_cf rtp_thread;
    struct rtpp_proc_thread_cf rtcp_thread;
    struct rtpp_proc_wakeup *wakeup_cf;
    int npkts_relayed_idx;
};

static void rtpp_proc_async_dtor(struct rtpp_proc_async_cf *);
static int rtpp_proc_async_nudge(struct rtpp_proc_async *);

static void
flush_rstats(struct rtpp_stats *sobj, struct rtpp_proc_rstats *rsp)
{

    FLUSH_STAT(sobj, rsp->npkts_rcvd);
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
    int tstate;
    struct rtpp_timestamp rtime;

    tcp = (struct rtpp_proc_thread_cf *)arg;
    proc_cf = tcp->proc_cf;
    cfsp = proc_cf->cf_save;
    stats_cf = cfsp->rtpp_stats;
    rstats = &tcp->rstats;

    memset(&rtime, '\0', sizeof(rtime));

    RTPP_DBGCODE(netio) {
        last_ctick = 0;
    }

    for (;;) {
        tstate = atomic_load(&tcp->tstate);
        CALL_SMETHOD(cfsp->sessinfo, sync_polltbl, &tcp->ptbl, tcp->pipe_type);
        if (tstate == TSTATE_CEASE) {
            break;
        }

        ndrain = 1;

        nready = 0;
        RTPP_DBGCODE(netio > 1) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_DBUG, "run %lld " \
              "polling for %d %s file descriptors", \
              last_ctick, tcp->ptbl.curlen, PP_NAME(tcp->pipe_type));
        }
        nready = rtpp_epoll_wait(tcp->ptbl.epfd, tcp->events, tcp->events_alloc, -1);
        RTPP_DBGCODE(netio) {
            RTPP_DBGCODE(netio > 1 || nready > 0) {
                RTPP_LOG(cfsp->glog, RTPP_LOG_DBUG, "run %lld " \
                  "polling for %d %s file descriptors: %d descriptors are ready", \
                  last_ctick, tcp->ptbl.curlen, PP_NAME(tcp->pipe_type), nready);
            }
        }
        if (nready < 0 && errno == EINTR) {
            continue;
        }
        if (nready == 0)
            goto next;

        rtpp_timestamp_get(&rtime);
        RTPP_DBG_ASSERT(rtime.wall > 0 && rtime.mono > 0);

        sender = rtpp_anetio_pick_sender(proc_cf->pub.netio);
        process_rtp_only(cfsp, &tcp->ptbl, &rtime, ndrain, sender, rstats,
          tcp->events, nready);

        rtpp_anetio_pump_q(sender);
        flush_rstats(stats_cf, rstats);

        if (nready == tcp->events_alloc) {
            struct epoll_event *tep;

            tep = realloc(tcp->events, sizeof(tcp->events[0]) * tcp->events_alloc * 2);
            if (tep != NULL) {
                tcp->events = tep;
                tcp->events_alloc *= 2;
            }
        }

next:
        RTPP_DBGCODE(netio) {
            last_ctick++;
        }
    }
    rtpp_polltbl_free(&tcp->ptbl);
}

void
rtpp_proc_async_setprocname(pthread_t thread_id, const char *pname)
{
#if HAVE_PTHREAD_SETNAME_NP
    const char ppr[] = "rtpp_proc: ";
    char *ptrname = alloca(sizeof(ppr) + strlen(pname));
    if (ptrname != NULL) {
        sprintf(ptrname, "%s%s", ppr, pname);
        (void)pthread_setname_np(thread_id, ptrname);
    }
#endif
}

static int
rtpp_proc_async_thread_init(const struct rtpp_cfg *cfsp, const struct rtpp_proc_async_cf *proc_cf,
  struct rtpp_proc_thread_cf *tcp, int pipe_type)
{
    struct epoll_event epevent;

    tcp->ptbl.epfd = rtpp_epoll_create();
    if (tcp->ptbl.epfd < 0)
        goto e0;
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, tcp->ptbl.wakefd) != 0)
        goto e1;
    epevent.events = EPOLLIN;
    epevent.data.ptr = NULL;
    if (rtpp_epoll_ctl(tcp->ptbl.epfd, EPOLL_CTL_ADD, tcp->ptbl.wakefd[0], &epevent) != 0)
        goto e2;

    tcp->proc_cf = proc_cf;
    tcp->pipe_type = pipe_type;

    init_rstats(cfsp->rtpp_stats, &tcp->rstats);

    tcp->events_alloc = 16;
    tcp->events = rtpp_zmalloc(sizeof(tcp->events[0]) * tcp->events_alloc);
    if (tcp->events == NULL)
        goto e2;

    if (pthread_create(&tcp->thread_id, NULL, (void *(*)(void *))&rtpp_proc_async_run, tcp) != 0) {
        goto e3;
    }
    rtpp_proc_async_setprocname(tcp->thread_id, PP_NAME(pipe_type));
    return (0);

e3:
    free(tcp->events);
e2:
    close(tcp->ptbl.wakefd[0]);
    close(tcp->ptbl.wakefd[1]);
e1:
    close(tcp->ptbl.epfd);
e0:
    return (-1);
}

static void
rtpp_proc_async_thread_destroy(struct rtpp_proc_thread_cf *tcp)
{
    int tstate = atomic_load(&tcp->tstate);

    assert(tstate == TSTATE_RUN);
    close(tcp->ptbl.wakefd[1]);
    atomic_store(&tcp->tstate, TSTATE_CEASE);
    pthread_join(tcp->thread_id, NULL);
    free(tcp->events);
}

static struct pproc_act
relay_packet(const struct pkt_proc_ctx *pktxp)
{
    struct rtpp_stream *stp_out = pktxp->strmp_out;
    struct rtpp_stream *stp_in = pktxp->strmp_in;
    struct rtp_packet *packet = pktxp->pktp;

    CALL_SMETHOD(stp_in->ttl, reset);
    if (stp_out == NULL) {
        return PPROC_ACT_DROP;
    }

    /*
     * Check that we have some address to which packet is to be
     * sent out, drop otherwise.
     */
    if (!CALL_SMETHOD(stp_out, issendable)) {
        return PPROC_ACT_DROP;
    }
    CALL_SMETHOD(stp_out, send_pkt, packet->sender, packet);
    if ((pktxp->flags & PPROC_FLAG_LGEN) == 0) {
        CALL_SMETHOD(stp_in->pcount, reg_reld);
        if (pktxp->rsp != NULL) {
            pktxp->rsp->npkts_relayed.cnt++;
        } else {
            struct rtpp_proc_async_cf *proc_cf = pktxp->pproc->arg;
            CALL_SMETHOD(proc_cf->cf_save->rtpp_stats, updatebyidx,
              proc_cf->npkts_relayed_idx, 1);
        }
    }
    return PPROC_ACT_TAKE;
}

static struct pproc_act
record_packet(const struct pkt_proc_ctx *pktxp)
{
    struct rtpp_stream *stp_out = pktxp->strmp_out;
    struct rtpp_stream *stp_in = pktxp->strmp_in;

    if (stp_in->rrc != NULL && stp_out != NULL) {
        if (!CALL_SMETHOD(stp_out, isplayer_active)) {
            CALL_SMETHOD(stp_in->rrc, pktwrite, pktxp);
        }
    }
    return PPROC_ACT_NOP;
}

struct rtpp_proc_async *
rtpp_proc_async_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = rtpp_rzmalloc(sizeof(*proc_cf), PVT_RCOFFS(proc_cf));
    if (proc_cf == NULL)
        return (NULL);

    proc_cf->npkts_relayed_idx = CALL_SMETHOD(cfsp->rtpp_stats, getidxbyname, "npkts_relayed");
    if (proc_cf->npkts_relayed_idx < 0)
        goto e0;

    proc_cf->pub.netio = rtpp_netio_async_init(cfsp, 1);
    if (proc_cf->pub.netio == NULL) {
        goto e0;
    }
    RTPP_OBJ_DTOR_ATTACH(&proc_cf->pub, rtpp_netio_async_destroy, proc_cf->pub.netio);

    proc_cf->cf_save = cfsp;

    const struct packet_processor_if relay_packet_poi = {
        .descr = "relay_packet",
        .arg = (void *)proc_cf,
        .key = (void *)&relay_packet,
        .enqueue = &relay_packet
    };
    if (CALL_SMETHOD(cfsp->pproc_manager, reg, PPROC_ORD_RELAY, &relay_packet_poi) < 0)
        goto e0;

    const struct packet_processor_if record_packet_poi = {
        .descr = "record_packet",
        .arg = (void *)proc_cf,
        .key = (void *)&record_packet,
        .enqueue = &record_packet
    };
    if (CALL_SMETHOD(cfsp->pproc_manager, reg, PPROC_ORD_WITNESS, &record_packet_poi) < 0)
        goto e1;

    if (rtpp_proc_async_thread_init(cfsp, proc_cf, &proc_cf->rtp_thread, PIPE_RTP) != 0) {
        goto e2;
    }
    RTPP_OBJ_DTOR_ATTACH(&proc_cf->pub, rtpp_proc_async_thread_destroy, &proc_cf->rtp_thread);

    if (rtpp_proc_async_thread_init(cfsp, proc_cf, &proc_cf->rtcp_thread, PIPE_RTCP) != 0) {
        goto e2;
    }
    RTPP_OBJ_DTOR_ATTACH(&proc_cf->pub, rtpp_proc_async_thread_destroy, &proc_cf->rtcp_thread);

    proc_cf->wakeup_cf = rtpp_proc_wakeup_ctor(proc_cf->rtp_thread.ptbl.wakefd[1],
      proc_cf->rtcp_thread.ptbl.wakefd[1]);
    if (proc_cf->wakeup_cf == NULL)
        goto e2;
    RTPP_OBJ_DTOR_ATTACH_OBJ(&proc_cf->pub, proc_cf->wakeup_cf);

    RTPP_OBJ_BORROW(&proc_cf->pub, cfsp->rtpp_stats);
    RTPP_OBJ_BORROW(&proc_cf->pub, cfsp->pproc_manager);

    RTPP_OBJ_DTOR_ATTACH(&proc_cf->pub, rtpp_proc_async_dtor, proc_cf);

    proc_cf->pub.nudge = &rtpp_proc_async_nudge;
    return (&proc_cf->pub);
e2:
    CALL_SMETHOD(cfsp->pproc_manager, unreg, record_packet_poi.key);
e1:
    CALL_SMETHOD(cfsp->pproc_manager, unreg, relay_packet_poi.key);
e0:
    RTPP_OBJ_DECREF(&proc_cf->pub);
    return (NULL);
}

static void
rtpp_proc_async_dtor(struct rtpp_proc_async_cf *proc_cf)
{
    CALL_SMETHOD(proc_cf->cf_save->pproc_manager, unreg, record_packet);
    CALL_SMETHOD(proc_cf->cf_save->pproc_manager, unreg, relay_packet);
}

static int
rtpp_proc_async_nudge(struct rtpp_proc_async *pub)
{
    struct rtpp_proc_async_cf *proc_cf;
    int nres;

    PUB2PVT(pub, proc_cf);
    nres = CALL_SMETHOD(proc_cf->wakeup_cf, nudge);
    return (nres);
}
