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

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stream.h"
#include "rtpp_pcount.h"
#include "rtpp_socket.h"
#include "rtpp_session.h"
#include "rtpp_pipe.h"
#include "rtpp_epoll.h"
#include "rtpp_debug.h"
#include "advanced/pproc_manager.h"
#include "advanced/packet_processor.h"

struct rtpp_proc_ready_lst {
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
};

static void
rxmit_packets(const struct rtpp_cfg *cfsp, struct rtpp_stream *stp,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp)
{
    int ndrain;
    struct rtp_packet *packet = NULL;
    struct pkt_proc_ctx pktx = {
        .strmp_in = stp,
        .strmp_out = CALL_SMETHOD(stp, get_sender, cfsp),
        .rsp = rsp
    };
    /* Repeat since we may have several packets queued on the same socket */
    ndrain = -1;
    do {
        if (ndrain < 0) {
            ndrain = drain_repeat - 1;
        } else {
            ndrain -= 1;
        }

	packet = CALL_SMETHOD(stp, rx, cfsp->rtcp_streams_wrt, dtime, rsp);
	if (packet == NULL) {
            /* Move on to the next session */
            break;
        }
        if (packet == RTPP_S_RX_DCONT) {
            ndrain += 1;
            continue;
        }
        packet->sender = sender;
        pktx.pktp = packet;
        CALL_SMETHOD(stp->pproc_manager, handle, &pktx);
    } while (ndrain > 0);
    if (pktx.strmp_out != NULL) {
        RTPP_OBJ_DECREF(pktx.strmp_out);
    }
    return;
}

void
process_rtp_only(const struct rtpp_cfg *cfsp, struct rtpp_polltbl *ptbl,
  const struct rtpp_timestamp *dtime, int drain_repeat, struct sthread_args *sender,
  struct rtpp_proc_rstats *rsp, struct epoll_event events[], int nready)
{
    int readyfd, ndrained;
    struct rtpp_session *sp;
    struct rtpp_stream *stp;
    struct rtpp_socket *iskt;

    for (readyfd = 0; readyfd < nready; readyfd++) {
        struct epoll_event *ep = &events[readyfd];
        if ((ep->events & EPOLLIN) == 0)
            continue;
        if (ep->data.ptr == NULL) {
            int nudge_data, rsize;

            rsize = read(ptbl->wakefd[0], &nudge_data, sizeof(nudge_data));
            RTPP_DBG_ASSERT(rsize == sizeof(nudge_data) || rsize == 0);
            if (rsize > 0 && rsize == sizeof(nudge_data)) {
                atomic_store(&ptbl->served_i_wake, nudge_data);
            }
            continue;
        }
        iskt = ep->data.ptr;
        uint64_t stuid = CALL_SMETHOD(iskt, get_stuid);
        stp = CALL_SMETHOD(ptbl->streams_wrt, get_by_idx, stuid);
        if (stp == NULL)
            continue;
        sp = CALL_SMETHOD(cfsp->sessions_wrt, get_by_idx, stp->seuid);
        if (sp == NULL) {
            RTPP_OBJ_DECREF(stp);
            continue;
        }
        if (sp->complete != 0) {
            rxmit_packets(cfsp, stp, dtime, drain_repeat, sender, rsp);
            if (stp->resizer != NULL) {
                struct pkt_proc_ctx pktx = {
                    .strmp_in = stp,
                    .strmp_out = CALL_SMETHOD(stp, get_sender, cfsp),
                    .rsp = rsp
                };

                while ((pktx.pktp = rtp_resizer_get(stp->resizer, dtime->mono)) != NULL) {
                    pktx.pktp->sender = sender;
                    if (CALL_SMETHOD(stp->pproc_manager, handleat, &pktx,
                      PPROC_ORD_RESIZE + 1).a & PPROC_ACT_TAKE_v)
                        rsp->npkts_resizer_out.cnt++;
                }

                if (pktx.strmp_out != NULL)
                    RTPP_OBJ_DECREF(pktx.strmp_out);
            }
            RTPP_OBJ_DECREF(sp);
        } else {
            const char *proto;

            RTPP_OBJ_DECREF(sp);
            proto = CALL_SMETHOD(stp, get_proto);
            ndrained = CALL_SMETHOD(iskt, drain, proto, stp->log);
            if (ndrained > 0) {
                rsp->npkts_discard.cnt += ndrained;
            }
        }
        RTPP_OBJ_DECREF(stp);
    }
}
