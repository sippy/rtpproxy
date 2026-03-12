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

#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config_pp.h"

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_util.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_modman.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_stats.h"
#include "rtpp_session.h"
#include "rtpp_pipe.h"
#include "rtpp_network.h"
#include "rtpp_mallocs.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc.h"
#include "commands/rpcpv1_ul_subc_copy.h"
#include "commands/rpcpv1_delete.h"
#include "commands/rpcpv1_ul_subc_set.h"

struct rtpp_subcommand_ul_lstate {
    struct rtpp_refcnt *rcnt;
    struct rtpp_command scmd;
};

static int
rtpp_command_ul_subc_pre_parse(const rtpp_str_t *call_id,
  const rtpp_str_t *from_tag, const rtpp_str_t *to_tag,
  const struct rtpp_command_args *subc_args, struct rtpp_command_ul_pcmd *pcmd)
{

    if (call_id == NULL || from_tag == NULL || to_tag == NULL)
        return (-1);
    if (subc_args->c != 3)
        return (-1);
    if (subc_args->v[0].len < 1)
        return (-1);
    if (subc_args->v[0].s[0] != 'L' && subc_args->v[0].s[0] != 'l')
        return (-1);

    memset(pcmd, '\0', sizeof(*pcmd));
    pcmd->cmods = subc_args->v[0].s + 1;
    pcmd->op = LOOKUP;
    pcmd->call_id = call_id;
    pcmd->from_tag = from_tag;
    pcmd->to_tag = to_tag;
    pcmd->addr = rtpp_str_fix(&subc_args->v[1]);
    pcmd->port = rtpp_str_fix(&subc_args->v[2]);
    return (0);
}

static int
rtpp_command_ul_as_subc(const struct after_success_h_args *ap,
  const struct rtpp_subc_ctx *scp)
{
    const struct rtpp_cfg *cfsp;
    struct rtpp_subcommand_ul_lstate *lsp;
    int sidx, rval;

    lsp = (struct rtpp_subcommand_ul_lstate *)ap->dyn;
    RTPP_DBG_ASSERT(scp->env->sessp != NULL);
    RTPP_DBG_ASSERT(lsp != NULL);
    cfsp = (const struct rtpp_cfg *)ap->stat;
    if (scp->env->sessp->rtp->stream[0] == scp->env->strmp_in) {
        sidx = 0;
    } else if (scp->env->sessp->rtp->stream[1] == scp->env->strmp_in) {
        sidx = 1;
    } else {
        return (-1);
    }
    lsp->scmd.sp = scp->env->sessp;
    rval = rtpp_command_ul_handle_impl(cfsp, &lsp->scmd, sidx);
    if (rval == 0) {
        if (format_ul_reply_result(lsp->scmd.cca.opts.ul,
          scp->resp->buf_t, sizeof(scp->resp->buf_t)) != 0)
            return -1;
        struct rtpp_stream *t = scp->env->strmp_in;
        scp->env->strmp_in = scp->env->strmp_out;
        scp->env->strmp_out = t;
    }
    return (rval);
}

static int
rtpp_command_ul_look_subc_parse(const struct rtpp_cfg *cfsp,
  struct rtpp_command *cmd, const struct rtpp_command_args *subc_args,
  struct after_success_h *asp)
{
    struct rtpp_subcommand_ul_lstate *lsp;
    struct rtpp_command_ul_pcmd pcmd;
    struct ul_opts *ulop;
    int ecode = 0;

    if (cmd->cca.op != UPDATE)
        goto e0;
    if (rtpp_command_ul_subc_pre_parse(cmd->cca.call_id, cmd->cca.from_tag,
      cmd->cca.to_tag, subc_args, &pcmd) != 0)
        goto e0;
    lsp = rtpp_rzmalloc(sizeof(struct rtpp_subcommand_ul_lstate),
      offsetof(struct rtpp_subcommand_ul_lstate, rcnt));
    if (lsp == NULL)
        goto e0;
    lsp->scmd = (struct rtpp_command){.glog = cmd->glog, .reply = cmd->reply};
    ulop = rtpp_command_ul_opts_parse_inner(cfsp, &lsp->scmd, &pcmd, &ecode);
    if (ulop == NULL)
        goto e1;
    lsp->scmd.reply = NULL;
    lsp->scmd.laddr = cmd->laddr;
    lsp->scmd.dtime = cmd->dtime;
    lsp->scmd.cca.op = pcmd.op;
    lsp->scmd.cca.opts.ul = ulop;
    lsp->scmd.cca.call_id = cmd->cca.call_id;
    lsp->scmd.cca.from_tag = cmd->cca.from_tag;
    lsp->scmd.cca.to_tag = cmd->cca.to_tag;
    lsp->scmd.raddr = cmd->raddr;
    lsp->scmd.csp = cmd->csp;
    RTPP_OBJ_DTOR_ATTACH_s(lsp, (rtpp_refcnt_dtor_t)&rtpp_command_ul_opts_free,
      ulop);
    asp->args.stat = (void *)cfsp;
    asp->args.dyn = lsp;
    asp->handler = rtpp_command_ul_as_subc;
    if (RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, lsp) != 0) {
        RTPP_OBJ_DECREF(lsp);
        return -1;
    }
    return (0);
e1:
    free(lsp);
e0:
    return (-1);
}

#if ENABLE_MODULE_IF
static int
handle_mod_subc_parse(const struct rtpp_cfg *cfsp, const char *ip,
  struct after_success_h *asp)
{
    int mod_id, inst_id;
    const char *cp;

    if (atoi_safe_sep(ip, &mod_id, ':', &cp) != ATOI_OK)
        return (-1);
    if (atoi_safe(cp, &inst_id) != ATOI_OK)
        return (-1);
    if (mod_id < 1 || inst_id < 1)
        return (-1);
    if (CALL_METHOD(cfsp->modules_cf, get_ul_subc_h, (unsigned)mod_id,
        (unsigned)inst_id, asp) != 0)
        return (-1);
    return (0);
}
#endif

int
rtpp_subcommand_ul_opts_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  const struct rtpp_command_args *subc_args, struct after_success_h *asp)
{
    struct delete_opts *dop;
    struct rtpp_subcommand_set *sop;

    switch(subc_args->v[0].s[0]) {
    case 'M':
    case 'm':
#if ENABLE_MODULE_IF
        return (handle_mod_subc_parse(cfsp, &subc_args->v[0].s[1], asp));
#else
        RTPP_LOG(cfsp->glog, RTPP_LOG_WARN, "module command, but modules are not " \
          "compiled in: %s", subc_args->v[0].s);
        return (-1);
#endif
        break;

    case 'D':
    case 'd':
        if (subc_args->c != 1)
            return (-1);
        dop = rtpp_command_del_opts_parse(NULL, subc_args);
        if (dop == NULL)
            return (-1);
        asp->args.dyn = dop;
        if (RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, dop) != 0) {
            RTPP_OBJ_DECREF(dop);
            return (-1);
        }
        asp->args.stat = (void *)cfsp;
        asp->handler = handle_delete_as_subc;
        break;

    case 'S':
    case 's':
        if (subc_args->c != 2 || subc_args->v[0].len < 1 || subc_args->v[0].len > 2)
            return (-1);
        sop = handle_set_subc_parse(cfsp, &subc_args->v[0].s[1], &subc_args->v[1], asp);
        if (sop == NULL)
            return (-1);
        asp->args.dyn = sop;
        if (RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, sop) != 0) {
            RTPP_OBJ_DECREF(sop);
             return (-1);
        }
        break;

    case 'L':
    case 'l':
        return (rtpp_command_ul_look_subc_parse(cfsp, cmd, subc_args, asp));

    case 'C':
    case 'c':
        return (rtpp_command_ul_copy_subc_parse(cfsp, cmd, subc_args, asp));

    default:
        return (-1);
    }
    return (0);
}
