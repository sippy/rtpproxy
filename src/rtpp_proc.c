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
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtp_resizer.h"
#include "rtpp_cfg.h"
#include "rtpp_defines.h"
#include "rtpp_proc.h"
#include "rtpp_record.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_socket.h"
#include "rtpp_session.h"
#include "rtpp_ttl.h"
#include "rtpp_pipe.h"
#include "advanced/po_manager.h"

struct rtpp_proc_ready_lst {
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
};

static void send_packet(const struct rtpp_cfg *, struct rtpp_stream *,
  struct rtp_packet *, struct sthread_args *, struct rtpp_proc_rstats *);

static void
rxmit_packets(const struct rtpp_cfg *cfsp, struct rtpp_stream *stp,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp, const struct rtpp_session *sp)
{
    int ndrain;
    struct rtp_packet *packet = NULL;
    struct po_mgr_pkt_ctx pktx;

    /* Repeat since we may have several packets queued on the same socket */
    ndrain = -1;
    do {
        if (ndrain < 0) {
            ndrain = drain_repeat - 1;
        } else {
            ndrain -= 1;
        }

	packet = CALL_SMETHOD(stp, rx, cfsp->rtcp_streams_wrt, dtime,
          rsp);
	if (packet == NULL) {
            /* Move on to the next session */
            return;
        }
        if (packet == RTPP_S_RX_DCONT) {
            ndrain += 1;
            continue;
        }
        pktx.sessp = sp;
        pktx.strmp = stp;
        pktx.pktp = packet;
        CALL_METHOD(cfsp->observers, observe, &pktx);
        send_packet(cfsp, stp, packet, sender, rsp);
    } while (ndrain > 0);
    return;
}

static struct rtpp_stream *
get_sender(const struct rtpp_cfg *cfsp, struct rtpp_stream *stp)
{
    if (stp->pipe_type == PIPE_RTP) {
       return (CALL_METHOD(cfsp->rtp_streams_wrt, get_by_idx,
         stp->stuid_sendr));
    }
    return (CALL_METHOD(cfsp->rtcp_streams_wrt, get_by_idx,
      stp->stuid_sendr));
}

static void
send_packet(const struct rtpp_cfg *cfsp, struct rtpp_stream *stp_in,
  struct rtp_packet *packet, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    struct rtpp_stream *stp_out;

    CALL_METHOD(stp_in->ttl, reset);

    stp_out = get_sender(cfsp, stp_in);
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
    if (!CALL_SMETHOD(stp_out, issendable) || CALL_SMETHOD(stp_out, isplayer_active)) {
        goto e1;
    } else {
        CALL_SMETHOD(stp_out, send_pkt, sender, packet);
        CALL_METHOD(stp_in->pcount, reg_reld);
        rsp->npkts_relayed.cnt++;
    }
    RTPP_OBJ_DECREF(stp_out);
    return;

e1:
    RTPP_OBJ_DECREF(stp_out);
e0:
    RTPP_OBJ_DECREF(packet);
    CALL_METHOD(stp_in->pcount, reg_drop);
    rsp->npkts_discard.cnt++;
}

void
process_rtp_only(const struct rtpp_cfg *cfsp, struct rtpp_polltbl *ptbl,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    int readyfd, ndrained;
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
    struct rtp_packet *packet;
    struct rtpp_socket *iskt;

    for (readyfd = 0; readyfd < ptbl->curlen; readyfd++) {
        if ((ptbl->pfds[readyfd].revents & POLLIN) == 0)
            continue;
        stp = CALL_METHOD(ptbl->streams_wrt, get_by_idx,
          ptbl->mds[readyfd].stuid);
        if (stp == NULL)
            continue;
        sp = CALL_METHOD(cfsp->sessions_wrt, get_by_idx, stp->seuid);
        if (sp == NULL) {
            RTPP_OBJ_DECREF(stp);
            continue;
        }
        iskt = ptbl->mds[readyfd].skt;
        if (sp->complete != 0) {
            rxmit_packets(cfsp, stp, dtime, drain_repeat, sender, rsp, sp);
            RTPP_OBJ_DECREF(sp);
            if (stp->resizer != NULL) {
                while ((packet = rtp_resizer_get(stp->resizer, dtime->mono)) != NULL) {
                    send_packet(cfsp, stp, packet, sender, rsp);
                    rsp->npkts_resizer_out.cnt++;
                    packet = NULL;
                }
            }
        } else {
            const char *proto;

            RTPP_OBJ_DECREF(sp);
            proto = CALL_SMETHOD(stp, get_proto);
            ndrained = CALL_METHOD(iskt, drain, proto, stp->log);
            if (ndrained > 0) {
                rsp->npkts_discard.cnt += ndrained;
            }
        }
        RTPP_OBJ_DECREF(stp);
    }
}
