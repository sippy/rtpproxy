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
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_ecodes.h"
#include "commands/rpcpv1_copy.h"
#include "commands/rpcpv1_record.h"
#include "rtpp_hash_table.h"
#include "rtpp_session.h"

struct record_ematch_arg {
    int nrecorded;
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
    struct record_opts *rop;
    const struct rtpp_cfg *cfsp;
};

static int
rtpp_cmd_record_ematch(void *dp, void *ap)
{
    struct rtpp_session *spa;
    int idx;
    struct record_ematch_arg *rep;

    spa = (struct rtpp_session *)dp;
    rep = (struct record_ematch_arg *)ap;

    if (compare_session_tags(spa->from_tag, rep->from_tag, NULL) != 0) {
        idx = 1;
    } else if (rep->to_tag != NULL &&
      (compare_session_tags(spa->from_tag, rep->to_tag, NULL)) != 0) {
        idx = 0;
    } else {
        return(RTPP_HT_MATCH_CONT);
    }
    if (handle_copy(rep->cfsp, NULL, spa, idx, NULL, rep->rop) == 0) {
        rep->nrecorded++;
    }
    return(RTPP_HT_MATCH_CONT);
}

int
handle_record(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    struct record_ematch_arg rea;
    struct common_cmd_args *ccap = &cmd->cca;
    struct record_opts *rop = (struct record_opts *)ccap->opts.record;

    memset(&rea, '\0', sizeof(rea));
    rea.from_tag = ccap->from_tag;
    rea.to_tag = ccap->to_tag;
    rea.rop = rop;
    rea.cfsp = cfsp;
    CALL_SMETHOD(cfsp->sessions_ht, foreach_key_str, ccap->call_id,
      rtpp_cmd_record_ematch, &rea);
    if (rea.nrecorded == 0) {
        return -1;
    }
    CALL_SMETHOD(cmd->reply, deliver_ok);
    return 0;
}

struct record_opts *
rtpp_command_record_opts_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  const struct rtpp_command_args *ap)
{
    struct record_opts *rop;
    const char *cp;

    rop = rtpp_rzmalloc(sizeof(struct record_opts), PUB_RCOFFS(rop));
    if (rop == NULL) {
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    for (cp = ap->v[0].s + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 's':
        case 'S':
            rop->record_single_file = RSF_MODE_DFLT(cfsp);;
            break;

        case 'p':
        case 'P':
            if (cmd->cca.op == RECORD) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "RECORD: command modifier `%c' is not allowed in RECORD",
                  *cp);
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_2);
                goto err_undo_1;
            }
            rop->reply_port = 1;
            break;

        default:
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
              "RECORD: unknown command modifier `%c'", *cp);
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_3);
            goto err_undo_1;
        }
    }
    return (rop);

err_undo_1:
    RTPP_OBJ_DECREF(rop);
err_undo_0:
    return (NULL);
}
