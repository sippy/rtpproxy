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
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_proc.h"
#include "rtpp_record.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_session.h"
#include "rtpp_ttl.h"
#include "rtpp_pipe.h"
#include "rtpp_acct_rtcp.h"
#include "rtpp_list.h"
#include "rtpp_module_if.h"

struct rtpp_proc_ready_lst {
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
};

static void send_packet(struct cfg *, struct rtpp_stream *,
  struct rtp_packet *, struct sthread_args *, struct rtpp_proc_rstats *);

static void
rxmit_packets(struct cfg *cf, struct rtpp_stream *stp,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp, const char *call_id)
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

	packet = CALL_SMETHOD(stp, rx, cf->stable->rtcp_streams_wrt, dtime,
          rsp);
	if (packet == NULL) {
            /* Move on to the next session */
            return;
        }
        if (packet == RTPP_S_RX_DCONT) {
            ndrain += 1;
            continue;
        }
        send_packet(cf, stp, packet, sender, rsp);
        if (stp->pipe_type == PIPE_RTCP && !RTPP_LIST_IS_EMPTY(cf->stable->modules_cf)) {
            struct rtpp_acct_rtcp *rarp;
            struct rtpp_module_if *mif;

            rarp = rtpp_acct_rtcp_ctor(call_id, packet);
            if (rarp == NULL) {
                continue;
            }
            mif = RTPP_LIST_HEAD(cf->stable->modules_cf);
            CALL_METHOD(mif, do_acct_rtcp, rarp);
        }
    } while (ndrain > 0);
    return;
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
    if (!CALL_SMETHOD(stp_out, issendable) || CALL_SMETHOD(stp_out, isplayer_active)) {
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

void
process_rtp_only(struct cfg *cf, struct rtpp_polltbl *ptbl,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    int readyfd, ndrained;
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
    struct rtp_packet *packet;

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
            rxmit_packets(cf, stp, dtime, drain_repeat, sender, rsp, sp->call_id);
            CALL_SMETHOD(sp->rcnt, decref);
            if (stp->resizer != NULL) {
                while ((packet = rtp_resizer_get(stp->resizer, dtime->mono)) != NULL) {
                    send_packet(cf, stp, packet, sender, rsp);
                    rsp->npkts_resizer_out.cnt++;
                    packet = NULL;
                }
            }
        } else {
            CALL_SMETHOD(sp->rcnt, decref);
            ndrained = CALL_SMETHOD(stp, drain_skt);
            if (ndrained > 0) {
                rsp->npkts_discard.cnt += ndrained;
            }
        }
        CALL_SMETHOD(stp->rcnt, decref);
    }
}
