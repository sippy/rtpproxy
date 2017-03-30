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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_defines.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_log.h"
#include "rtpp_command.h"
#include "rtpp_command_delete.h"
#include "rtpp_command_private.h"
#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_pipe.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_weakref.h"

struct delete_ematch_arg {
    int ndeleted;
    const char *from_tag;
    const char *to_tag;
    int weak;
    struct rtpp_weakref_obj *sessions_wrt;
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
    if ((cmpr1 = compare_session_tags(spa->tag, dep->from_tag, &medianum)) != 0) {
        idx = 1;
        cmpr = cmpr1;
    } else if (dep->to_tag != NULL &&
      (cmpr1 = compare_session_tags(spa->tag, dep->to_tag, &medianum)) != 0) {
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
        dep->ndeleted++;
        return (RTPP_HT_MATCH_CONT);
    }
    RTPP_LOG(spa->log, RTPP_LOG_INFO,
      "forcefully deleting session %u on ports %d/%d",
       medianum, spa->rtp->stream[0]->port, spa->rtp->stream[1]->port);
    if (CALL_METHOD(dep->sessions_wrt, unreg, spa->seuid) != NULL) {
        dep->ndeleted++;
    }
    if (cmpr != 2) {
        return (RTPP_HT_MATCH_DEL | RTPP_HT_MATCH_BRK);
    }
    return (RTPP_HT_MATCH_DEL);
}

struct delete_opts {
    int weak;
};

int
handle_delete(struct cfg *cf, struct common_cmd_args *ccap)
{
    struct delete_ematch_arg dea;

    memset(&dea, '\0', sizeof(dea));
    dea.from_tag = ccap->from_tag;
    dea.to_tag = ccap->to_tag;
    dea.weak = ccap->opts.delete->weak;
    dea.sessions_wrt = cf->stable->sessions_wrt;
    CALL_METHOD(cf->stable->sessions_ht, foreach_key, ccap->call_id,
      rtpp_cmd_delete_ematch, &dea);
    rtpp_command_del_opts_free(ccap->opts.delete);
    ccap->opts.delete = NULL;
    return (dea.ndeleted == 0) ? -1 : 0;
}

struct delete_opts *
rtpp_command_del_opts_parse(struct rtpp_command *cmd)
{
    struct delete_opts *dlop;
    const char *cp;

    dlop = rtpp_zmalloc(sizeof(struct delete_opts));
    if (dlop == NULL) {
        reply_error(cmd, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    for (cp = cmd->argv[0] + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'w':
        case 'W':
            dlop->weak = 1;
            break;

        default:
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
              "DELETE: unknown command modifier `%c'", *cp);
            reply_error(cmd, ECODE_PARSE_4);
            goto err_undo_1;
        }
    }
    return (dlop);

err_undo_1:
    rtpp_command_del_opts_free(dlop);
err_undo_0:
    return (NULL);
}

void
rtpp_command_del_opts_free(struct delete_opts *dlop)
{

    free(dlop);
}
