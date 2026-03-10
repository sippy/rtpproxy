/*
 * Copyright (c) 2006-2025 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_codeptr.h"
#include "rtpp_debug.h"
#include "rtpp_util.h"
#include "rtpp_refcnt.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_session.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_str.h"
#include "rtpp_mallocs.h"
#include "rtpp_time.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"
#include "commands/rpcpv1_ul_subc_copy.h"

#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

struct rtpp_subcommand_ul_copy_pstate {
    struct rtpp_refcnt *rcnt;
    rtpp_str_const_t call_id;
    rtpp_str_const_t from_tag;
    rtpp_str_const_t to_tag;
};

struct rtpp_subc_ul_copy_fwd {
    struct pproc_manager *src_ppmgr;
    struct rtpp_stream *tgt_strmp_in;
    struct rtpp_stream *tgt_strmp_out;
    char src_key;
    char tgt_key;
};

struct rtpp_subcommand_ul_copy_state {
    struct rtpp_refcnt *rcnt;
    struct rtpp_subc_ul_copy_fwd fwd[2][2];
};

static struct pproc_act
ul_subc_drop_packets(const struct pkt_proc_ctx *pktxp)
{

    return (PPROC_ACT_DROP);
}

static struct pproc_act
ul_subc_copy_enqueue(const struct pkt_proc_ctx *pktxp)
{
    const struct rtpp_subc_ul_copy_fwd *fwdp;
    struct pkt_proc_ctx tpktx;

    fwdp = (const struct rtpp_subc_ul_copy_fwd *)pktxp->pproc->arg;
    RTPP_DBG_ASSERT(fwdp != NULL);
    RTPP_DBG_ASSERT(fwdp->tgt_strmp_in != NULL);
    RTPP_DBG_ASSERT(fwdp->tgt_strmp_out != NULL);

    RTPP_OBJ_INCREF(pktxp->pktp);
    tpktx = (struct pkt_proc_ctx){
      .strmp_in = fwdp->tgt_strmp_in,
      .strmp_out = fwdp->tgt_strmp_out,
      .pktp = pktxp->pktp,
      .flags = pktxp->flags | PPROC_FLAG_LGEN | PPROC_FLAG_COW,
      .sender = pktxp->sender,
    };
    (void)CALL_SMETHOD(tpktx.strmp_in->pproc_manager, handleat, &tpktx,
      PPROC_ORD_PLAY + 1);
    return (PPROC_ACT_TEE);
}

static void
rtpp_subcommand_ul_copy_uninstall(struct rtpp_subcommand_ul_copy_state *csp)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            struct rtpp_subc_ul_copy_fwd *fwdp;

            fwdp = &csp->fwd[i][j];
            RTPP_DBG_ASSERT(fwdp->src_ppmgr != NULL);
            RTPP_DBG_ASSERT(fwdp->tgt_strmp_out != NULL);
            CALL_SMETHOD(fwdp->src_ppmgr, unreg, &fwdp->src_key);
            CALL_SMETHOD(fwdp->tgt_strmp_out->pproc_manager, unreg,
              &fwdp->tgt_key);
        }
    }
}

static void
rusc_on_tgt_sess_dtor(struct rtpp_subcommand_ul_copy_state *csp)
{

    rtpp_subcommand_ul_copy_uninstall(csp);
}

static int
rtpp_command_ul_copy_subc_pre_parse(struct rtpp_command *cmd,
  const struct rtpp_command_args *subc_args,
  struct rtpp_subcommand_ul_copy_pstate *csp)
{

    if (cmd->cca.op != UPDATE || cmd->cca.to_tag == NULL)
        return (-1);
    if (subc_args->c != 4 || subc_args->v[0].len != 1)
        return (-1);
    if (subc_args->v[0].s[0] != 'C' && subc_args->v[0].s[0] != 'c')
        return (-1);
    if (subc_args->v[1].len < 1 || subc_args->v[2].len < 1 || subc_args->v[3].len < 1)
        return (-1);

    csp->call_id = subc_args->v[1];
    csp->from_tag = subc_args->v[2];
    csp->to_tag = subc_args->v[3];
    return (0);
}

static int
rtpp_command_ul_copy_as_subc(const struct after_success_h_args *ashap,
  const struct rtpp_subc_ctx *rscp)
{
    const struct rtpp_cfg *cfsp;
    const struct rtpp_subcommand_ul_copy_pstate *psp;
    struct rtpp_subcommand_ul_copy_state *csp;
    struct pproc_manager *src_ppmgr[2][2];
    struct rtpp_stream *tgt_strmp[2][2];
    struct rtpp_stream_pair src_rtcp, tgt_rtcp;
    struct rtpp_session *ssp;
    struct rtpp_stream *src0, *src1, *tgt0, *tgt1;
    int sidx, rval;

    RTPP_DBG_ASSERT(rscp->env->sessp != NULL);
    RTPP_DBG_ASSERT(rscp->env->strmp_in != NULL);
    RTPP_DBG_ASSERT(rscp->env->strmp_out != NULL);

    cfsp = (const struct rtpp_cfg *)ashap->stat;
    psp = (const struct rtpp_subcommand_ul_copy_pstate *)ashap->dyn;
    RTPP_DBG_ASSERT(cfsp != NULL);
    RTPP_DBG_ASSERT(psp != NULL);

    sidx = find_stream(cfsp, rtpp_str_fix(&psp->call_id),
      rtpp_str_fix(&psp->from_tag), rtpp_str_fix(&psp->to_tag), &ssp);
    if (sidx == -1) {
        goto e0;
    }
    src0 = ssp->rtp->stream[sidx];
    src1 = ssp->rtp->stream[NOT(sidx)];
    tgt0 = rscp->env->strmp_in;
    tgt1 = rscp->env->strmp_out;
    src_rtcp = get_rtcp_pair(ssp, src0);
    tgt_rtcp = get_rtcp_pair(rscp->env->sessp, tgt0);
    if (src_rtcp.ret != 0 || tgt_rtcp.ret != 0 ||
      src_rtcp.in == NULL || src_rtcp.out == NULL ||
      tgt_rtcp.in == NULL || tgt_rtcp.out == NULL) {
        goto e1;
    }
    if (src0 == tgt0 || src0 == tgt1 || src1 == tgt0 || src1 == tgt1) {
        goto e1;
    }
    csp = rtpp_rzmalloc(sizeof(*csp), offsetof(struct rtpp_subcommand_ul_copy_state, rcnt));
    if (csp == NULL) {
        goto e1;
    }
    src_ppmgr[0][0] = src0->pproc_manager;
    src_ppmgr[0][1] = src1->pproc_manager;
    src_ppmgr[1][0] = src_rtcp.in->pproc_manager;
    src_ppmgr[1][1] = src_rtcp.out->pproc_manager;
    tgt_strmp[0][0] = tgt0;
    tgt_strmp[0][1] = tgt1;
    tgt_strmp[1][0] = tgt_rtcp.in;
    tgt_strmp[1][1] = tgt_rtcp.out;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            struct rtpp_subc_ul_copy_fwd *fwdp;

            fwdp = &csp->fwd[i][j];
            fwdp->src_ppmgr = src_ppmgr[i][j];
            fwdp->tgt_strmp_in = tgt_strmp[i][NOT(j)];
            fwdp->tgt_strmp_out = tgt_strmp[i][j];
            if (RTPP_OBJ_BORROW(csp, fwdp->src_ppmgr) != 0 ||
              RTPP_OBJ_BORROW(csp, fwdp->tgt_strmp_in) != 0 ||
              RTPP_OBJ_BORROW(csp, fwdp->tgt_strmp_out) != 0) {
                goto e2;
            }
        }
    }

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            struct rtpp_subc_ul_copy_fwd *fwdp;
            const struct packet_processor_if copy_poi = {
                .descr = "ul_subc_copy_inject",
                .rcnt = csp->rcnt,
                .arg = NULL,
                .key = NULL,
                .enqueue = &ul_subc_copy_enqueue
            };
            const struct packet_processor_if drop_poi = {
                .descr = "ul_subc_copy_drop",
                .rcnt = csp->rcnt,
                .arg = NULL,
                .key = NULL,
                .enqueue = &ul_subc_drop_packets
            };
            struct packet_processor_if lcopy_poi, ldrop_poi;

            fwdp = &csp->fwd[i][j];
            lcopy_poi = copy_poi;
            lcopy_poi.arg = fwdp;
            lcopy_poi.key = (void *)&fwdp->src_key;
            ldrop_poi = drop_poi;
            ldrop_poi.arg = fwdp;
            ldrop_poi.key = (void *)&fwdp->tgt_key;

            rval = CALL_SMETHOD(fwdp->src_ppmgr, reg, PPROC_ORD_WITNESS,
              &lcopy_poi);
            if (rval < 0)
                goto e3;
            rval = CALL_SMETHOD(fwdp->tgt_strmp_out->pproc_manager, reg,
              PPROC_ORD_PLAY, &ldrop_poi);
            if (rval < 0)
                goto e3;
        }
    }

    if (RTPP_OBJ_BORROW(rscp->env->sessp, csp) != 0) {
        goto e3;
    }
    if (RTPP_OBJ_DTOR_ATTACH(rscp->env->sessp,
      (rtpp_refcnt_dtor_t)&rusc_on_tgt_sess_dtor, csp) != 0) {
        goto e3;
    }
    RTPP_OBJ_DECREF(csp);
    RTPP_OBJ_DECREF(ssp);
    return (0);

e3:
    rtpp_subcommand_ul_copy_uninstall(csp);
e2:
    RTPP_OBJ_DECREF(csp);
e1:
    RTPP_OBJ_DECREF(ssp);
e0:
    return (-1);
}

int
rtpp_command_ul_copy_subc_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  const struct rtpp_command_args *subc_args, struct after_success_h *asp)
{
    struct rtpp_subcommand_ul_copy_pstate *csp;

    csp = rtpp_rzmalloc(sizeof(*csp), offsetof(struct rtpp_subcommand_ul_copy_pstate, rcnt));
    if (csp == NULL)
        goto e0;
    if (rtpp_command_ul_copy_subc_pre_parse(cmd, subc_args, csp) != 0)
        goto e1;
    if (RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, csp) != 0)
        goto e1;
    asp->args.stat = (void *)cfsp;
    asp->args.dyn = csp;
    asp->handler = rtpp_command_ul_copy_as_subc;
    return (0);
e1:
    RTPP_OBJ_DECREF(csp);
e0:
    return (-1);
}
