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
#include <poll.h>
#include <stdint.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_weakref.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtp_resizer.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_network.h"
#include "rtpp_proc.h"
#include "rtpp_record.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_socket.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_session.h"
#include "rtpp_ssrc.h"
#include "rtp_analyze.h"
#include "rtpp_analyzer.h"
#include "rtpp_ttl.h"
#include "rtpp_pipe.h"
#include "rtpp_netaddr.h"

struct rtpp_proc_ready_lst {
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
};

static void send_packet(struct cfg *, struct rtpp_stream *,
  struct rtp_packet *, struct sthread_args *, struct rtpp_proc_rstats *);

static int
fill_session_addr(struct cfg *cf, struct rtpp_stream *stp,
  struct rtp_packet *packet)
{
    struct rtpp_stream *stp_rtcp;
    int rval;

    CALL_SMETHOD(stp, fill_addr, packet);
    if (stp->stuid_rtcp == RTPP_UID_NONE) {
        return (0);
    }
    stp_rtcp = CALL_METHOD(cf->stable->rtcp_streams_wrt, get_by_idx,
      stp->stuid_rtcp);
    if (stp_rtcp == NULL) {
        return (0);
    }
    rval = CALL_SMETHOD(stp_rtcp, guess_addr, packet);
    CALL_SMETHOD(stp_rtcp->rcnt, decref);
    return (rval);
}

static void
rxmit_packets(struct cfg *cf, struct rtpp_stream *stp,
  double dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    int ndrain;
    struct rtp_packet *packet = NULL;

    /* Repeat since we may have several packets queued on the same socket */
    ndrain = -1;
    do {
        if (ndrain < 0) {
            ndrain = drain_repeat - 1;
        } else {
            ndrain -= 1;
        }

	packet = CALL_METHOD(stp->fd, rtp_recv, dtime, stp->laddr, stp->port);
	if (packet == NULL) {
            /* Move on to the next session */
            return;
        }
        rsp->npkts_rcvd.cnt++;

	if (!CALL_SMETHOD(stp->rem_addr, isempty)) {
	    /* Check that the packet is authentic, drop if it isn't */
	    if (stp->asymmetric == 0) {
                if (CALL_SMETHOD(stp->rem_addr, cmp, sstosa(&packet->raddr),
                  packet->rlen) != 0) {
		    if (CALL_SMETHOD(stp, islatched) && \
                      CALL_SMETHOD(stp, check_latch_override, packet) == 0) {
			/*
			 * Continue, since there could be good packets in
			 * queue.
			 */
                        ndrain += 1;
                        CALL_METHOD(stp->pcount, reg_ignr);
                        rsp->npkts_discard.cnt++;
			goto discard_and_continue;
		    }
		    /* Signal that an address has to be updated */
		    fill_session_addr(cf, stp, packet);
		} else if (!CALL_SMETHOD(stp, islatched)) {
                    CALL_SMETHOD(stp, latch, dtime, packet);
		}
	    } else {
		/*
		 * For asymmetric clients don't check
		 * source port since it may be different.
		 */
                if (!CALL_SMETHOD(stp->rem_addr, cmphost, sstosa(&packet->raddr))) {
		    /*
		     * Continue, since there could be good packets in
		     * queue.
		     */
                    ndrain += 1;
                    CALL_METHOD(stp->pcount, reg_ignr);
                    rsp->npkts_discard.cnt++;
		    goto discard_and_continue;
                }
	    }
	    CALL_METHOD(stp->pcnt_strm, reg_pktin, packet);
	} else {
	    CALL_METHOD(stp->pcnt_strm, reg_pktin, packet);
#if 0
	    stp->addr = malloc(packet->rlen);
	    if (stp->addr == NULL) {
		CALL_METHOD(stp->pcount, reg_drop);
		RTPP_LOG(stp->log, RTPP_LOG_ERR,
		  "can't allocate memory for remote address - "
		  "discarding packet");
                rsp->npkts_discard.cnt++;
		goto discard;
	    }
#endif
	    /* Update address recorded in the session */
	    fill_session_addr(cf, stp, packet);
	}
        if (stp->analyzer != NULL) {
            if (CALL_METHOD(stp->analyzer, update, packet) == UPDATE_SSRC_CHG) {
                CALL_SMETHOD(stp, latch, dtime, packet);
            }
        }
        rtpp_stream_latch_sync(stp, dtime, packet);
	if (stp->resizer != NULL) {
	    rtp_resizer_enqueue(stp->resizer, &packet, rsp);
            if (packet == NULL) {
                rsp->npkts_resizer_in.cnt++;
            }
        }
	if (packet != NULL) {
	    send_packet(cf, stp, packet, sender, rsp);
            packet = NULL;
        }
discard_and_continue:
        if (packet != NULL) {
            rtp_packet_free(packet);
        }
    } while (ndrain > 0);
    return;

#if 0
discard:
    rtp_packet_free(packet);
    return;
#endif
}

static struct rtpp_stream *
get_sender(struct cfg *cf, struct rtpp_stream *stp)
{
    if (stp->pipe_type == PIPE_RTP) {
       return (CALL_METHOD(cf->stable->rtp_streams_wrt, get_by_idx,
         stp->stuid_sendr));
    }
    return (CALL_METHOD(cf->stable->rtcp_streams_wrt, get_by_idx,
      stp->stuid_sendr));
}

static void
send_packet(struct cfg *cf, struct rtpp_stream *stp_in,
  struct rtp_packet *packet, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    struct rtpp_stream *stp_out;

    CALL_METHOD(stp_in->ttl, reset);

    stp_out = get_sender(cf, stp_in);
    if (stp_out == NULL) {
        goto e0;
    }

    if (stp_in->rrc != NULL) {
        if (!CALL_SMETHOD(stp_out, isplayer_active)) {
            CALL_METHOD(stp_in->rrc, write, stp_out, packet);
        }
    }

    /*
     * Check that we have some address to which packet is to be
     * sent out, drop otherwise.
     */
    if (CALL_SMETHOD(stp_out->rem_addr, isempty) || CALL_SMETHOD(stp_out, isplayer_active)) {
        goto e1;
    } else {
        CALL_SMETHOD(stp_out, send_pkt, sender, packet);
        CALL_METHOD(stp_in->pcount, reg_reld);
        rsp->npkts_relayed.cnt++;
    }
    CALL_SMETHOD(stp_out->rcnt, decref);
    return;

e1:
    CALL_SMETHOD(stp_out->rcnt, decref);
e0:
    rtp_packet_free(packet);
    CALL_METHOD(stp_in->pcount, reg_drop);
    rsp->npkts_discard.cnt++;
}

static int
drain_socket(struct rtpp_socket *rfd, struct rtpp_proc_rstats *rsp)
{
    struct rtp_packet *packet;
    int ndrained;

    ndrained = 0;
    for (;;) {
        packet = CALL_METHOD(rfd, rtp_recv, 0.0, NULL, 0);
        if (packet == NULL)
            break;
        rsp->npkts_discard.cnt++;
        ndrained++;
        rtp_packet_free(packet);
    }
    return (ndrained);
}

void
process_rtp_only(struct cfg *cf, struct rtpp_polltbl *ptbl, double dtime,
  int drain_repeat, struct sthread_args *sender, struct rtpp_proc_rstats *rsp)
{
    int readyfd;
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
    struct rtp_packet *packet;
#if RTPP_DEBUG
    const char *proto;
    int fd, ndrained;
#endif

    for (readyfd = 0; readyfd < ptbl->curlen; readyfd++) {
        if ((ptbl->pfds[readyfd].revents & POLLIN) == 0)
            continue;
        stp = CALL_METHOD(ptbl->streams_wrt, get_by_idx,
          ptbl->mds[readyfd].stuid);
        if (stp == NULL)
            continue;
        sp = CALL_METHOD(cf->stable->sessions_wrt, get_by_idx, stp->seuid);
        if (sp == NULL) {
            CALL_SMETHOD(stp->rcnt, decref);
            continue;
        }
        if (sp->complete != 0) {
            rxmit_packets(cf, stp, dtime, drain_repeat, sender, rsp);
            CALL_SMETHOD(sp->rcnt, decref);
            if (stp->resizer != NULL) {
                while ((packet = rtp_resizer_get(stp->resizer, dtime)) != NULL) {
                    send_packet(cf, stp, packet, sender, rsp);
                    rsp->npkts_resizer_out.cnt++;
                    packet = NULL;
                }
            }
        } else {
            CALL_SMETHOD(sp->rcnt, decref);
#if RTPP_DEBUG
            proto = CALL_SMETHOD(stp, get_proto);
            fd = CALL_METHOD(stp->fd, getfd);
            RTPP_LOG(stp->log, RTPP_LOG_DBUG, "Draining %s socket %d", proto,
              fd);
            ndrained = drain_socket(stp->fd, rsp);
            if (ndrained > 0) {
                RTPP_LOG(stp->log, RTPP_LOG_DBUG, "Draining %s socket %d: %d "
                  "packets discarded", proto, fd, ndrained);
            }
#else
            drain_socket(stp->fd, rsp);
#endif

        }
        CALL_SMETHOD(stp->rcnt, decref);
    }
}
