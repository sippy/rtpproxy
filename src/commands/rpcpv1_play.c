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
 */

#include <sys/socket.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_command.h"
#include "rtpp_command_ecodes.h"
#include "commands/rpcpv1_play.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_stream.h"

struct play_opts {
    int count;
    const rtpp_str_t *pname;
    const rtpp_str_t *codecs;
};

struct play_opts *
rtpp_command_play_opts_parse(struct rtpp_command *cmd)
{
    struct play_opts *plop;
    const char *tcp;
    char *cp;

    plop = rtpp_zmalloc(sizeof(struct play_opts));
    if (plop == NULL) {
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    plop->count = 1;
    plop->pname = rtpp_str_fix(&cmd->args.v[2]);
    plop->codecs = rtpp_str_fix(&cmd->args.v[3]);
    tcp = &(cmd->args.v[0].s[1]);
    if (*tcp != '\0') {
        plop->count = strtol(tcp, &cp, 10);
        if (cp == tcp || *cp != '\0') {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_6);
            goto err_undo_1;
        }
    }
    return (plop);

err_undo_1:
    rtpp_command_play_opts_free(plop);
err_undo_0:
    return (NULL);
}

void
rtpp_command_play_opts_free(struct play_opts *plop)
{

    free(plop);
}

void
rtpp_command_play_handle(struct rtpp_stream *rsp, struct rtpp_command *cmd,
  const struct rtpp_cfg *cfsp)
{
    const char *codecs;
    int ptime;
    struct play_opts *plop;

    CALL_SMETHOD(rsp, handle_noplay);
    plop = cmd->cca.opts.play;
    if (strcmp(plop->codecs->s, "session") == 0) {
        if (rsp->codecs == NULL) {
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_5);
            goto freeplop;
        }
        codecs = rsp->codecs;
        ptime = rsp->ptime;
    } else {
        codecs = plop->codecs->s;
        ptime = -1;
    }
    const struct r_stream_h_play_args pa = {
        .codecs = codecs,
        .pname = plop->pname->s,
        .playcount = plop->count,
        .cmd = cmd,
        .ptime = ptime,
        .guid = cfsp->guid,
    };
    if (plop->count != 0 && CALL_SMETHOD(rsp, handle_play, &pa) != 0) {
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PLRFAIL);
        goto freeplop;
    }
    CALL_SMETHOD(cmd->reply, deliver_ok);
freeplop:
    rtpp_command_play_opts_free(plop);
}
