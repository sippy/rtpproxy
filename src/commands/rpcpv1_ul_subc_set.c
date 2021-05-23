/*
 * Copyright (c) 2025 Sippy Software, Inc., http://www.sippysoft.com
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

#include "config.h"

#include "rtpp_codeptr.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_pipe.h"
#include "rtpp_socket.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_ttl.h"
#include "rtpp_command.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_args.h"
#include "rtpp_command_private.h"
#include "rtpp_mallocs.h"
#include "rtpp_util.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc_set.h"

static int
strmp_settos(const struct rtpp_subc_ctx *rscp, struct rtpp_stream *strmp, int val)
{
    if (strmp->laddr->sa_family != AF_INET)
        return (-1);
    struct rtpp_socket *fd = CALL_SMETHOD(strmp, get_skt, HEREVAL);
    if (fd == NULL)
        goto out;
    int tres = CALL_SMETHOD(fd, settos, val);
    RTPP_OBJ_DECREF(fd);
    if (tres == -1) {
        RTPP_ELOG(rscp->log, RTPP_LOG_ERR, "unable to set TOS to %d", val);
        return (-1);
    }
out:
    strmp->tos = val;
    return (0);
}

static int
rtpp_subcommand_set_handler(const struct after_success_h_args *ashap,
  const struct rtpp_subc_ctx *rscp)
{
    const struct rtpp_subcommand_set *tap;
    struct rtpp_stream *strmp, *strmp1 = NULL;

    tap = (struct rtpp_subcommand_set *)ashap->dyn;
    switch (tap->direction) {
    case SET_FORWARD:
        strmp = rscp->strmp_in;
        strmp1 = rscp->strmp_out;
        break;

    case SET_REVERSE:
        strmp = rscp->strmp_out;
        if (strmp == NULL)
            return (-1);
        strmp1 = rscp->strmp_in;
        break;

    default:
        abort();
    }

    switch (tap->param) {
    case SET_PRM_TTL:
        strmp->stream_ttl = tap->val;
        if (strmp1 != NULL && strmp1->ttl == strmp->ttl)
            strmp1->stream_ttl = tap->val;
        CALL_SMETHOD(strmp->ttl, reset_with, tap->val);
        break;

    case SET_PRM_TOS:
        if (strmp_settos(rscp, strmp, tap->val) != 0)
            return (-1);
        struct rtpp_stream_pair rtcp = get_rtcp_pair(rscp->sessp, strmp);
        if (rtcp.ret != 0 || rtcp.in == NULL)
            break;
        if (strmp_settos(rscp, rtcp.in, tap->val) != 0)
            return (-1);
        break;

    default:
        abort();
    }
    return (0);
}

struct rtpp_subcommand_set *
handle_set_subc_parse(const struct rtpp_cfg *cfsp, const char *cp,
  const rtpp_str_const_t *v, struct after_success_h *asp)
{
    struct rtpp_subcommand_set set_arg, *tap;

    if (cp[0] == 'r' || cp[0] == 'R') {
        set_arg.direction = SET_REVERSE;
    } else {
        set_arg.direction = SET_FORWARD;
    }
    if (v->len < 5)
        return (NULL);
    if (memcmp(v->s, "ttl=", 4) == 0) {
        set_arg.param = SET_PRM_TTL;
        cp = v->s + 4;
    } else if (memcmp(v->s, "tos=", 4) == 0) {
        set_arg.param = SET_PRM_TOS;
        cp = v->s + 4;
    } else {
        return (NULL);
    }
    if (atoi_safe(cp, &set_arg.val) != ATOI_OK)
        return (NULL);
    if (set_arg.val <= 0)
        return (NULL);
    tap = rtpp_rzmalloc(sizeof(set_arg), offsetof(struct rtpp_subcommand_set, rcnt));
    if (tap == NULL)
        return (NULL);
    tap->val = set_arg.val;
    tap->direction = set_arg.direction;
    tap->param = set_arg.param;
    asp->handler = rtpp_subcommand_set_handler;
    return (tap);
}
