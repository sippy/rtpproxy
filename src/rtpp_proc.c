/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <netinet/in.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_weakref.h"
#include "rtp.h"
#include "rtp_info.h"
#include "rtp_packet.h"
#include "rtp_resizer.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_netio_async.h"
#include "rtpp_proc.h"
#include "rtpp_record.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_stats.h"
#include "rtpp_util.h"
#include "rtpp_analyzer.h"

struct rtpp_proc_ready_lst {
    struct rtpp_session_obj *sp;
    int ridx;
};

static void send_packet(struct cfg *, struct rtpp_session_obj *, int, \
  struct rtp_packet *, struct sthread_args *, struct rtpp_proc_rstats *);

static int
fill_session_addr(struct rtpp_session_obj *sp, struct rtp_packet *packet, int ridx)
{

    CALL_METHOD(sp->stream[ridx], fill_addr, packet);
    if (sp->rtcp == NULL) {
        return (0);
    }
    return (CALL_METHOD(sp->rtcp->stream[ridx], guess_addr, packet));
}

static struct rtpp_session_obj *
get_rtp(struct cfg *cf, struct rtpp_session_obj *sp)
{
    if (sp->rtcp != NULL) {
        return (sp);
    }
    return (CALL_METHOD(cf->stable->sessions_wrt, get_by_idx, sp->rtp_seuid));
}

static void
rxmit_packets(struct cfg *cf, struct rtpp_proc_ready_lst *rready, int rlen,
  double dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    int ndrain, rn, ridx;
    struct rtp_packet *packet = NULL;
    struct rtpp_session_obj *sp, *tsp;

    /* Repeat since we may have several packets queued on the same socket */
    ndrain = -1;
    for (rn = 0; rn < rlen; rn += (ndrain > 0) ? 0 : 1) {
        if (ndrain < 0) {
            ndrain = drain_repeat - 1;
        } else {
            ndrain -= 1;
        }
	if (packet != NULL)
	    rtp_packet_free(packet);

        sp = rready[rn].sp;
        ridx = rready[rn].ridx;

	packet = rtp_recv(sp->stream[ridx]->fd);
	if (packet == NULL) {
            /* Move on to the next session */
            ndrain = -1;
	    continue;
        }
	packet->laddr = sp->stream[ridx]->laddr;
	packet->rport = sp->stream[ridx]->port;
	packet->rtime = dtime;
        rsp->npkts_rcvd.cnt++;

	if (sp->stream[ridx]->addr != NULL) {
	    /* Check that the packet is authentic, drop if it isn't */
	    if (sp->stream[ridx]->asymmetric == 0) {
		if (memcmp(sp->stream[ridx]->addr, &packet->raddr, packet->rlen) != 0) {
		    if (sp->stream[ridx]->latch_info.latched != 0 && \
                      CALL_METHOD(sp->stream[ridx], check_latch_override, packet) == 0) {
			/*
			 * Continue, since there could be good packets in
			 * queue.
			 */
                        ndrain += 1;
                        sp->pcount.nignored++;
                        rsp->npkts_discard.cnt++;
			continue;
		    }
		    /* Signal that an address has to be updated */
		    fill_session_addr(sp, packet, ridx);
		} else if (sp->stream[ridx]->latch_info.latched == 0) {
                    CALL_METHOD(sp->stream[ridx], latch, dtime, packet);
		}
	    } else {
		/*
		 * For asymmetric clients don't check
		 * source port since it may be different.
		 */
		if (!ishostseq(sp->stream[ridx]->addr, sstosa(&packet->raddr))) {
		    /*
		     * Continue, since there could be good packets in
		     * queue.
		     */
                    ndrain += 1;
                    sp->pcount.nignored++;
                    rsp->npkts_discard.cnt++;
		    continue;
                }
	    }
	    sp->stream[ridx]->npkts_in++;
	} else {
	    sp->stream[ridx]->npkts_in++;
	    sp->stream[ridx]->addr = malloc(packet->rlen);
	    if (sp->stream[ridx]->addr == NULL) {
		sp->pcount.ndropped++;
		RTPP_LOG(sp->log, RTPP_LOG_ERR,
		  "can't allocate memory for remote address - "
		  "removing session");
                tsp = get_rtp(cf, sp);
                if (tsp != NULL) {
		    remove_session(cf, tsp);
                    if (tsp != sp)
                        CALL_METHOD(sp->rcnt, decref);
                }
		/* Move on to the next session, sp is invalid now */
                ndrain = -1;
                rsp->npkts_discard.cnt++;
		continue;
	    }
	    /* Update address recorded in the session */
	    fill_session_addr(sp, packet, ridx);
	}
        if (sp->stream[ridx]->analyzer != NULL) {
            rtpp_analyzer_update(sp, sp->stream[ridx]->analyzer, packet);
        }
	if (sp->stream[ridx]->resizer != NULL) {
	    rtp_resizer_enqueue(sp->stream[ridx]->resizer, &packet, rsp);
            if (packet == NULL) {
                rsp->npkts_resizer_in.cnt++;
            }
        }
	if (packet != NULL) {
	    send_packet(cf, sp, ridx, packet, sender, rsp);
            packet = NULL;
        }
    }
    if (packet != NULL)
        rtp_packet_free(packet);
}

static void
send_packet(struct cfg *cf, struct rtpp_session_obj *sp, int ridx,
  struct rtp_packet *packet, struct sthread_args *sender, 
  struct rtpp_proc_rstats *rsp)
{
    int sidx;
    struct rtpp_session_obj *tsp;

    tsp = get_rtp(cf, sp);
    if (tsp == NULL)
        return;
    tsp->stream[ridx]->ttl = cf->stable->max_ttl;

    /* Select socket for sending packet out. */
    sidx = (ridx == 0) ? 1 : 0;

    if (sp->stream[ridx]->rrc != NULL && !CALL_METHOD(tsp->stream[sidx], isplayer_active)) {
        rwrite(sp, sp->stream[ridx]->rrc, packet, sp->stream[sidx]->addr, sp->stream[sidx]->laddr,
          sp->stream[sidx]->port, sidx);
    }

    /*
     * Check that we have some address to which packet is to be
     * sent out, drop otherwise.
     */
    if (sp->stream[sidx]->addr == NULL || CALL_METHOD(tsp->stream[sidx], isplayer_active)) {
        rtp_packet_free(packet);
	sp->pcount.ndropped++;
        rsp->npkts_discard.cnt++;
    } else {
        rtpp_anetio_send_pkt(sender, sp->stream[sidx]->fd, sp->stream[sidx]->addr, \
          SA_LEN(sp->stream[sidx]->addr), packet);
        sp->pcount.nrelayed++;
        rsp->npkts_relayed.cnt++;
    }
    if (tsp != sp) {
        CALL_METHOD(tsp->rcnt, decref);
    }
}

static void
drain_socket(int rfd, struct rtpp_proc_rstats *rsp)
{
    struct rtp_packet *packet;

    for (;;) {
        packet = rtp_recv(rfd);
        if (packet == NULL)
            break;
        rsp->npkts_discard.cnt++;
        rtp_packet_free(packet);
    }
}

#define	RR_ADD_PUSH(__rready, __rready_len, __sp, __ridx) { \
  __rready[__rready_len].sp = __sp; \
  __rready[rready_len].ridx = __ridx; \
  __rready_len += 1; \
  if (__rready_len == 10) { \
    rxmit_packets(cf, __rready, __rready_len, dtime, drain_repeat, sender, rsp); \
    __rready_len = 0; \
  } }\

static int
find_ridx(struct cfg *cf, int readyfd, struct rtpp_session_obj *sp)
{
    int ridx;

    for (ridx = 0; ridx < 2; ridx++)
        if (cf->sessinfo->pfds_rtp[readyfd].fd == sp->stream[ridx]->fd)
            break;
    /*
     * Can't happen.
     */
    assert(ridx != 2);

    return (ridx);
}

void
process_rtp_only(struct cfg *cf, double dtime, int drain_repeat, \
  struct sthread_args *sender, struct rtpp_proc_rstats *rsp)
{
    int readyfd, ridx, rready_len;
    struct rtpp_session_obj *sp;
    struct rtp_packet *packet;
    struct rtpp_proc_ready_lst rready[10];

    rready_len = 0;
    pthread_mutex_lock(&cf->sessinfo->lock);
    for (readyfd = 0; readyfd < cf->sessinfo->nsessions; readyfd++) {
        sp = cf->sessinfo->sessions[readyfd];

        if (cf->sessinfo->pfds_rtp[readyfd].fd == -1) {
            /* Deleted session, move one */
            continue;
        }
        if (sp->complete != 0) {
            ridx = find_ridx(cf, readyfd, sp);
            if ((cf->sessinfo->pfds_rtp[readyfd].revents & POLLIN) != 0) {
                RR_ADD_PUSH(rready, rready_len, sp, ridx);
            }
            if (sp->stream[ridx]->resizer != NULL) {
                while ((packet = rtp_resizer_get(sp->stream[ridx]->resizer, dtime)) != NULL) {
                    send_packet(cf, sp, ridx, packet, sender, rsp);
                    rsp->npkts_resizer_out.cnt++;
                    packet = NULL;
                }
            }
        } else if ((cf->sessinfo->pfds_rtp[readyfd].revents & POLLIN) != 0) {
#if RTPP_DEBUG
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable->glog, "Draining RTP socket %d", cf->sessinfo->pfds_rtp[readyfd].fd);
#endif
            drain_socket(cf->sessinfo->pfds_rtp[readyfd].fd, rsp);
        }
    }
    if (rready_len > 0) {
        rxmit_packets(cf, rready, rready_len, dtime, drain_repeat, sender, rsp);
        rready_len = 0;
    }
    pthread_mutex_unlock(&cf->sessinfo->lock);
}

void
process_rtp(struct cfg *cf, double dtime, int alarm_tick, int drain_repeat, \
  struct sthread_args *sender, struct rtpp_proc_rstats *rsp)
{
    int readyfd, skipfd, ridx, rready_len;
    struct rtpp_session_obj *sp;
    struct rtp_packet *packet;
    struct rtpp_proc_ready_lst rready[10];

    /* Relay RTP/RTCP */
    skipfd = 0;
    rready_len = 0;
    pthread_mutex_lock(&cf->sessinfo->lock);
    for (readyfd = 0; readyfd < cf->sessinfo->nsessions; readyfd++) {
	sp = cf->sessinfo->sessions[readyfd];

	if (alarm_tick != 0 && sp != NULL && sp->stream[0]->sidx == readyfd) {
	    if (get_ttl(sp) == 0) {
		RTPP_LOG(sp->log, RTPP_LOG_INFO, "session timeout");
                if (sp->timeout_data.notify_target != NULL) {
		    CALL_METHOD(cf->stable->rtpp_notify_cf, schedule,
                      sp->timeout_data.notify_target, sp->timeout_data.notify_tag);
                }
		remove_session(cf, sp);
		CALL_METHOD(cf->stable->rtpp_stats, updatebyname, "nsess_timeout", 1);
	    } else {
		if (sp->stream[0]->ttl != 0)
		    sp->stream[0]->ttl--;
		if (sp->stream[1]->ttl != 0)
		    sp->stream[1]->ttl--;
	    }
	}

	if (cf->sessinfo->pfds_rtp[readyfd].fd == -1) {
	    /* Deleted session, count and move one */
	    skipfd++;
	    continue;
	}

	/* Find index of the call leg within a session */
        ridx = find_ridx(cf, readyfd, sp);

	/* Compact pfds[] and sessions[] by eliminating removed sessions */
	if (skipfd > 0) {
	    cf->sessinfo->pfds_rtp[readyfd - skipfd] = cf->sessinfo->pfds_rtp[readyfd];
	    cf->sessinfo->pfds_rtcp[readyfd - skipfd] = cf->sessinfo->pfds_rtcp[readyfd];
	    cf->sessinfo->sessions[readyfd - skipfd] = cf->sessinfo->sessions[readyfd];
	    sp->stream[ridx]->sidx = readyfd - skipfd;
	    sp->rtcp->stream[ridx]->sidx = readyfd - skipfd;
	}

	if (sp->complete != 0) {
	    if ((cf->sessinfo->pfds_rtp[readyfd].revents & POLLIN) != 0) {
                RR_ADD_PUSH(rready, rready_len, sp, ridx);
            }
            if ((cf->sessinfo->pfds_rtcp[readyfd].revents & POLLIN) != 0) {
                RR_ADD_PUSH(rready, rready_len, sp->rtcp, ridx);
            }
	    if (sp->stream[ridx]->resizer != NULL) {
		while ((packet = rtp_resizer_get(sp->stream[ridx]->resizer, dtime)) != NULL) {
		    send_packet(cf, sp, ridx, packet, sender, rsp);
                    rsp->npkts_resizer_out.cnt++;
		    packet = NULL;
		}
	    }
	} else if ((cf->sessinfo->pfds_rtp[readyfd].revents & POLLIN) != 0) {
#if RTPP_DEBUG
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable->glog, "Draining RTP socket %d", cf->sessinfo->pfds_rtp[readyfd].fd);
#endif
            drain_socket(cf->sessinfo->pfds_rtp[readyfd].fd, rsp);
        } else if ((cf->sessinfo->pfds_rtcp[readyfd].revents & POLLIN) != 0) {
#if RTPP_DEBUG
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable->glog, "Draining RTCP socket %d", cf->sessinfo->pfds_rtcp[readyfd].fd);
#endif
            drain_socket(cf->sessinfo->pfds_rtcp[readyfd].fd, rsp);
        }
    }
    if (rready_len > 0) {
        rxmit_packets(cf, rready, rready_len, dtime, drain_repeat, sender, rsp);
        rready_len = 0;
    }
    /* Trim any deleted sessions at the end */
    cf->sessinfo->nsessions -= skipfd;
    pthread_mutex_unlock(&cf->sessinfo->lock);
}
