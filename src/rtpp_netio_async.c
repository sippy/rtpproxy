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
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_queue.h"
#include "rtpp_network.h"
#include "rtpp_netio_async.h"
#include "rtpp_time.h"
#include "rtpp_mallocs.h"
#include "rtpp_debug.h"
#ifdef RTPP_DEBUG
#include "rtpp_math.h"
#endif

struct sthread_args {
    struct rtpp_queue *out_q;
    struct rtpp_log *glog;
    int dmode;
#if RTPP_DEBUG_timers
    struct recfilter average_load;
#endif
    struct rtpp_wi *sigterm;
};

#define SEND_THREADS 1

struct rtpp_anetio_cf {
    pthread_t thread_id[SEND_THREADS];
    struct sthread_args args[SEND_THREADS];
};

#define RTPP_ANETIO_MAX_RETRY 3

static void
rtpp_anetio_sthread(struct sthread_args *args)
{
    int n, nsend, i, send_errno, nretry;
    struct rtpp_wi *wi, *wis[100];
#if RTPP_DEBUG_timers
    double tp[3], runtime, sleeptime;
    long run_n;

    runtime = sleeptime = 0.0;
    run_n = 0;
    tp[0] = getdtime();
#endif
    for (;;) {
        nsend = rtpp_queue_get_items(args->out_q, wis, 100, 0);
#if RTPP_DEBUG_timers
        tp[1] = getdtime();
#endif

        for (i = 0; i < nsend; i++) {
	    wi = wis[i];
            if (wi->wi_type == RTPP_WI_TYPE_SGNL) {
                rtpp_wi_free(wi);
                goto out;
            }
            nretry = 0;
            do {
                n = sendto(wi->sock, wi->msg, wi->msg_len, wi->flags,
                  wi->sendto, wi->tolen);
                send_errno = (n < 0) ? errno : 0;
#if RTPP_DEBUG_netio >= 1
                if (wi->debug != 0) {
                    char daddr[MAX_AP_STRBUF];

                    addrport2char_r(wi->sendto, daddr, sizeof(daddr), ':');
                    if (n < 0) {
                        RTPP_ELOG(wi->log, RTPP_LOG_DBUG,
                          "sendto(%d, %p, %lld, %d, %p (%s), %d) = %d",
                          wi->sock, wi->msg, (long long)wi->msg_len, wi->flags,
                          wi->sendto, daddr, wi->tolen, n);
                    } else if (n < wi->msg_len) {
                        RTPP_LOG(wi->log, RTPP_LOG_DBUG,
                          "sendto(%d, %p, %lld, %d, %p (%s), %d) = %d: short write",
                          wi->sock, wi->msg, (long long)wi->msg_len, wi->flags,
                          wi->sendto, daddr, wi->tolen, n);
#if RTPP_DEBUG_netio >= 2
                    } else {
                        RTPP_LOG(wi->log, RTPP_LOG_DBUG,
                          "sendto(%d, %p, %d, %d, %p (%s), %d) = %d",
                          wi->sock, wi->msg, wi->msg_len, wi->flags, wi->sendto, daddr,
                          wi->tolen, n);
#endif
                    }
                }
#endif
                if (n >= 0) {
                    wi->nsend--;
                } else {
                    /* "EPERM" is Linux thing, yield and retry */
                    if ((send_errno == EPERM || send_errno == ENOBUFS)
                      && nretry < RTPP_ANETIO_MAX_RETRY) {
                        sched_yield();
                        nretry++;
                    } else {
                        break;
                    }
                }
            } while (wi->nsend > 0);
            rtpp_wi_free(wi);
        }
#if RTPP_DEBUG_timers
        sleeptime += tp[1] - tp[0];
        tp[0] = getdtime();
        runtime += tp[0] - tp[1];
        if ((run_n % 10000) == 0) {
            RTPP_LOG(args->glog, RTPP_LOG_DBUG, "rtpp_anetio_sthread(%p): run %ld aload = %f filtered = %f", \
              args, run_n, runtime / (runtime + sleeptime), args->average_load.lastval);
        }
        if (runtime + sleeptime > 1.0) {
            recfilter_apply(&args->average_load, runtime / (runtime + sleeptime));
            runtime = sleeptime = 0.0;
        }
        run_n += 1;
#endif
    }
out:
    return;
}

int
rtpp_anetio_sendto(struct rtpp_anetio_cf *netio_cf, int sock, const void *msg, \
  size_t msg_len, int flags, const struct sockaddr *sendto, socklen_t tolen)
{
    struct rtpp_wi *wi;

    wi = rtpp_wi_malloc(sock, msg, msg_len, flags, sendto, tolen);
    if (wi == NULL) {
        return (-1);
    }
#if RTPP_DEBUG_netio >= 1
    wi->debug = 1;
    wi->log = netio_cf->args[0].glog;
    CALL_SMETHOD(wi->log->rcnt, incref);
#if RTPP_DEBUG_netio >= 2
    RTPP_LOG(netio_cf->args[0].glog, RTPP_LOG_DBUG, "malloc(%d, %p, %d, %d, %p, %d) = %p",
      sock, msg, msg_len, flags, sendto, tolen, wi);
    RTPP_LOG(netio_cf->args[0].glog, RTPP_LOG_DBUG, "sendto(%d, %p, %d, %d, %p, %d)",
      wi->sock, wi->msg, wi->msg_len, wi->flags, wi->sendto, wi->tolen);
#endif
#endif
    rtpp_queue_put_item(wi, netio_cf->args[0].out_q);
    return (0);
}

void
rtpp_anetio_pump(struct rtpp_anetio_cf *netio_cf)
{

    rtpp_queue_pump(netio_cf->args[0].out_q);
}

void
rtpp_anetio_pump_q(struct sthread_args *sender)
{

    rtpp_queue_pump(sender->out_q);
}

int
rtpp_anetio_send_pkt(struct sthread_args *sender, int sock, \
  const struct sockaddr *sendto, socklen_t tolen, struct rtp_packet *pkt,
  struct rtpp_refcnt *sock_rcnt, struct rtpp_log *plog)
{
    struct rtpp_wi *wi;
    int nsend;

    if (sender->dmode != 0 && pkt->size < LBR_THRS) {
        nsend = 2;
    } else {
        nsend = 1;
    }

    wi = rtpp_wi_malloc_pkt(sock, pkt, sendto, tolen, nsend, sock_rcnt);
    if (wi == NULL) {
        rtp_packet_free(pkt);
        return (-1);
    }
    /*
     * rtpp_wi_malloc_pkt() consumes pkt and returns wi, so no need to
     * call rtp_packet_free() here.
     */
#if RTPP_DEBUG_netio >= 2
    wi->debug = 1;
    if (plog == NULL) {
        plog = sender->glog;
    }
    CALL_SMETHOD(plog->rcnt, incref);
    wi->log = plog;
    RTPP_LOG(plog, RTPP_LOG_DBUG, "send_pkt(%d, %p, %d, %d, %p, %d)",
      wi->sock, wi->msg, wi->msg_len, wi->flags, wi->sendto, wi->tolen);
#endif
    rtpp_queue_put_item(wi, sender->out_q);
    return (0);
}

int
rtpp_anetio_send_pkt_na(struct sthread_args *sender, int sock, \
  struct rtpp_netaddr *sendto, struct rtp_packet *pkt,
  struct rtpp_refcnt *sock_rcnt, struct rtpp_log *plog)
{
    struct rtpp_wi *wi;
    int nsend;

    if (sender->dmode != 0 && pkt->size < LBR_THRS) {
        nsend = 2;
    } else {
        nsend = 1;
    }

    wi = rtpp_wi_malloc_pkt_na(sock, pkt, sendto, nsend, sock_rcnt);
    if (wi == NULL) {
        rtp_packet_free(pkt);
        return (-1);
    }
    /*
     * rtpp_wi_malloc_pkt() consumes pkt and returns wi, so no need to
     * call rtp_packet_free() here.
     */
#if RTPP_DEBUG_netio >= 2
    wi->debug = 1;
    if (plog == NULL) {
        plog = sender->glog;
    }
    CALL_SMETHOD(plog->rcnt, incref);
    wi->log = plog;
    RTPP_LOG(plog, RTPP_LOG_DBUG, "send_pkt(%d, %p, %d, %d, %p, %d)",
      wi->sock, wi->msg, wi->msg_len, wi->flags, wi->sendto, wi->tolen);
#endif
    rtpp_queue_put_item(wi, sender->out_q);
    return (0);
}

struct sthread_args *
rtpp_anetio_pick_sender(struct rtpp_anetio_cf *netio_cf)
{
    int min_len, i, l;
    struct sthread_args *sender;

    sender = &netio_cf->args[0];
    min_len = rtpp_queue_get_length(sender->out_q);
    if (min_len == 0) {
        return (sender);
    }
    for (i = 1; i < SEND_THREADS; i++) {
        l = rtpp_queue_get_length(netio_cf->args[i].out_q);
        if (l < min_len) {
            sender = &netio_cf->args[i];
            min_len = l;
        }
    }
    return (sender);
}

struct rtpp_anetio_cf *
rtpp_netio_async_init(struct cfg *cf, int qlen)
{
    struct rtpp_anetio_cf *netio_cf;
    int i, ri;

    netio_cf = rtpp_zmalloc(sizeof(*netio_cf));
    if (netio_cf == NULL)
        return (NULL);

    for (i = 0; i < SEND_THREADS; i++) {
        netio_cf->args[i].out_q = rtpp_queue_init(qlen, "RTPP->NET%.2d", i);
        if (netio_cf->args[i].out_q == NULL) {
            for (ri = i - 1; ri >= 0; ri--) {
                rtpp_queue_destroy(netio_cf->args[ri].out_q);
                CALL_SMETHOD(netio_cf->args[ri].glog->rcnt, decref);
            }
            goto e0;
        }
        CALL_SMETHOD(cf->stable->glog->rcnt, incref);
        netio_cf->args[i].glog = cf->stable->glog;
        netio_cf->args[i].dmode = cf->stable->dmode;
#if RTPP_DEBUG_timers
        recfilter_init(&netio_cf->args[i].average_load, 0.9, 0.0, 0);
#endif
    }

    for (i = 0; i < SEND_THREADS; i++) {
        netio_cf->args[i].sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
        if (netio_cf->args[i].sigterm == NULL) {
            for (ri = i - 1; ri >= 0; ri--) {
                rtpp_wi_free(netio_cf->args[ri].sigterm);
            }
            goto e1;
        }
    }

    cf->stable->rtpp_netio_cf = netio_cf;
    for (i = 0; i < SEND_THREADS; i++) {
        if (pthread_create(&(netio_cf->thread_id[i]), NULL, (void *(*)(void *))&rtpp_anetio_sthread, &netio_cf->args[i]) != 0) {
             for (ri = i - 1; ri >= 0; ri--) {
                 rtpp_queue_put_item(netio_cf->args[ri].sigterm, netio_cf->args[ri].out_q);
                 pthread_join(netio_cf->thread_id[ri], NULL);
             }
             for (ri = i; ri < SEND_THREADS; ri++) {
                 rtpp_wi_free(netio_cf->args[ri].sigterm);
             }
             goto e1;
        }
    }

    return (netio_cf);

#if 0
e2:
    for (i = 0; i < SEND_THREADS; i++) {
        rtpp_wi_free(netio_cf->args[i].sigterm);
    }
#endif
e1:
    for (i = 0; i < SEND_THREADS; i++) {
        rtpp_queue_destroy(netio_cf->args[i].out_q);
        CALL_SMETHOD(netio_cf->args[i].glog->rcnt, decref);
    }
e0:
    free(netio_cf);
    return (NULL);
}

void
rtpp_netio_async_destroy(struct rtpp_anetio_cf *netio_cf)
{
    int i;

    for (i = 0; i < SEND_THREADS; i++) {
        rtpp_queue_put_item(netio_cf->args[i].sigterm, netio_cf->args[i].out_q);
    }
    for (i = 0; i < SEND_THREADS; i++) {
        pthread_join(netio_cf->thread_id[i], NULL);
        rtpp_queue_destroy(netio_cf->args[i].out_q);
        CALL_SMETHOD(netio_cf->args[i].glog->rcnt, decref);
    }
    free(netio_cf);
}
