/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_defines.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_command.h"
#include "commands/rpcpv1_delete.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_sub.h"
#include "rtpp_hash_table.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_pipe.h"
#include "rtpp_session.h"
#include "rtpp_str.h"
#include "rtpp_codeptr.h"
#include "rtpp_stream.h"
#include "rtpp_weakref.h"
#include "rtpp_refcnt.h"

struct delete_ematch_arg {
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
    int weak;
    struct rtpp_weakref *sessions_wrt;
    /* Return value */
    struct {
        int ndeleted;
        struct rtpp_session *spa;
        int cmpr;
        unsigned int medianum;
    } res;
};

static int
rtpp_cmd_delete_ematch(void *dp, void *ap)
{
    unsigned int medianum;
    struct rtpp_session *spa;
    int cmpr, cmpr1, idx;
    struct delete_ematch_arg *dep;

    spa = (struct rtpp_session *)dp;
    dep = (struct delete_ematch_arg *)ap;

    medianum = 0;
    if ((cmpr1 = compare_session_tags(spa->from_tag, dep->from_tag, &medianum)) != 0) {
        idx = 1;
        cmpr = cmpr1;
    } else if (dep->to_tag != NULL &&
      (cmpr1 = compare_session_tags(spa->from_tag, dep->to_tag, &medianum)) != 0) {
        idx = 0;
        cmpr = cmpr1;
    } else {
        return (RTPP_HT_MATCH_CONT);
    }

    if (dep->weak)
        spa->rtp->stream[idx]->weak = 0;
    else
        spa->strong = 0;

    /*
     * This seems to be stable from reiterations, the only side
     * effect is less efficient work.
     */
    if (spa->strong || spa->rtp->stream[0]->weak || spa->rtp->stream[1]->weak) {
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "delete: medianum=%u: removing %s flag, seeing flags to"
          " continue session (strong=%d, weak=%d/%d)",
          medianum,
          dep->weak ? ( idx ? "weak[1]" : "weak[0]" ) : "strong",
          spa->strong, spa->rtp->stream[0]->weak, spa->rtp->stream[1]->weak);
        /* Skipping to next possible stream for this call */
        dep->res.ndeleted++;
        return (RTPP_HT_MATCH_CONT);
    }
    RTPP_OBJ_INCREF(spa);
    dep->res.spa = spa;
    dep->res.cmpr = cmpr;
    dep->res.medianum = medianum;
    return (RTPP_HT_MATCH_DEL | RTPP_HT_MATCH_BRK);
}

struct delete_opts_priv {
    struct delete_opts pub;
    int weak;
};

static int
do_delete(const struct rtpp_cfg *cfsp, const rtpp_str_t *call_id, struct delete_ematch_arg *dep)
{
    do {
        CALL_SMETHOD(cfsp->sessions_ht, foreach_key_str, call_id, rtpp_cmd_delete_ematch, dep);
        if (dep->res.spa == NULL)
            break;
        RTPP_LOG(dep->res.spa->log, RTPP_LOG_INFO,
          "forcefully deleting session %u on ports %d/%d", dep->res.medianum,
          dep->res.spa->rtp->stream[0]->port, dep->res.spa->rtp->stream[1]->port);
        if (CALL_SMETHOD(dep->sessions_wrt, unreg, dep->res.spa->seuid) != NULL) {
            dep->res.ndeleted++;
        }
        RTPP_OBJ_DECREF(dep->res.spa);
        dep->res.spa = NULL;
    } while (dep->res.cmpr == 2);

    return (dep->res.ndeleted == 0) ? -1 : 0;
}

int
handle_delete(const struct rtpp_cfg *cfsp, struct common_cmd_args *ccap)
{
    struct delete_opts_priv *dop;
    PUB2PVT(ccap->opts.delete, dop);
    struct delete_ematch_arg dea = {
        .from_tag = ccap->from_tag,
        .to_tag = ccap->to_tag,
        .weak = dop->weak,
        .sessions_wrt = cfsp->sessions_wrt,
    };

    int res = do_delete(cfsp, ccap->call_id, &dea);
    return res;
}

int
handle_delete_as_subc(const struct after_success_h_args *ap,
  const struct rtpp_subc_ctx *scp)
{
    const struct rtpp_cfg *cfsp = ap->stat;
    struct delete_opts_priv *dop;
    PUB2PVT((struct delete_opts *)ap->dyn, dop);
    struct delete_ematch_arg dea = {
        .from_tag = scp->sessp->from_tag,
        .weak = dop->weak,
        .sessions_wrt = cfsp->sessions_wrt
    };

    return do_delete(cfsp, scp->sessp->call_id, &dea);
}

struct delete_opts *
rtpp_command_del_opts_parse(struct rtpp_command *cmd, const struct rtpp_command_args *ap)
{
    struct delete_opts_priv *dlop;
    const char *cp;

    dlop = rtpp_rzmalloc(sizeof(struct delete_opts_priv), PVT_RCOFFS(dlop));
    if (dlop == NULL) {
        if (cmd != NULL)
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    for (cp = ap->v[0].s + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'w':
        case 'W':
            dlop->weak = 1;
            break;

        default:
            if (cmd != NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "DELETE: unknown command modifier `%c'", *cp);
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_4);
            }
            goto err_undo_1;
        }
    }
    return (&dlop->pub);

err_undo_1:
    RTPP_OBJ_DECREF(&dlop->pub);
err_undo_0:
    return (NULL);
}

