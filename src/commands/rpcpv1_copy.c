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
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_pipe.h"
#include "rtpp_record.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_socket.h"
#include "rtpp_bindaddrs.h"
#include "commands/rpcpv1_copy.h"
#include "commands/rpcpv1_record.h"

static int
get_args4remote(const struct rtpp_cfg *cfsp, const char *rname, struct rtpp_log *log,
  struct remote_copy_args *ap)
{
    char *tmp;
    const struct sockaddr *laddr;
    struct rtpp_socket *fds[2] = {0};

    rname += 4;
    strlcpy(ap->rhost, rname, sizeof(ap->rhost));
    tmp = strrchr(ap->rhost, ':');
    if (tmp == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "remote recording target specification should include port number");
        return (-1);
    }
    *tmp = '\0';

    laddr = CALL_METHOD(cfsp->bindaddrs_cf, local4remote, cfsp, log, AF_INET, ap->rhost, SERVICE);
    if (laddr == NULL)
        return (-1);
    int lport;
    if (rtpp_create_listener(cfsp, laddr, &lport, fds) != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "can't create listener");
        return (-1);
    }
    ap->rport = tmp + 1;
    ap->laddr = laddr;
    ap->lport = lport;
    ap->fds[0] = fds[0];
    ap->fds[1] = fds[1];
    return (0);
}

int
handle_copy(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd, struct rtpp_session *spa,
  int idx, const char *rname, const struct record_opts *rop)
{
    int remote;
    struct remote_copy_args rargs = {0};

    remote = (rname != NULL && strncmp("udp:", rname, 4) == 0)? 1 : 0;

    if (rop->reply_port != 0 && !remote) {
        RTPP_LOG(spa->log, RTPP_LOG_ERR,
          "RECORD: command modifier `p' is not allowed for non-remote recording");
        return (-1);
    }

    if (remote == 0 && rop->record_single_file != 0) {
        if (spa->rtp->stream[idx]->rrc != NULL)
            return (-1);
        if (spa->rtp->stream[NOT(idx)]->rrc != NULL) {
            RTPP_OBJ_INCREF(spa->rtp->stream[NOT(idx)]->rrc);
            spa->rtp->stream[idx]->rrc = spa->rtp->stream[NOT(idx)]->rrc;
        } else {
            spa->rtp->stream[idx]->rrc = rtpp_record_ctor(cfsp, NULL, spa, rname, idx, RECORD_BOTH);
            if (spa->rtp->stream[idx]->rrc == NULL) {
                return (-1);
            }
            RTPP_LOG(spa->log, RTPP_LOG_INFO,
              "starting recording RTP session on port %d", spa->rtp->stream[idx]->port);
        }
        assert(spa->rtcp->stream[idx]->rrc == NULL);
        if (cfsp->rrtcp != 0) {
            RTPP_OBJ_INCREF(spa->rtp->stream[idx]->rrc);
            spa->rtcp->stream[idx]->rrc = spa->rtp->stream[idx]->rrc;
            RTPP_LOG(spa->log, RTPP_LOG_INFO,
              "starting recording RTCP session on port %d", spa->rtcp->stream[idx]->port);
        }
        if (cmd != NULL)
            CALL_SMETHOD(cmd->reply, deliver_ok);
        return (0);
    }

    int rval = -1;
    if (remote)
        if (get_args4remote(cfsp, rname, spa->log, &rargs) != 0)
            return (-1);

    if (spa->rtp->stream[idx]->rrc == NULL) {
        spa->rtp->stream[idx]->rrc = rtpp_record_ctor(cfsp, &rargs, spa, rname, idx, RECORD_RTP);
        if (spa->rtp->stream[idx]->rrc == NULL) {
            goto out;
        }
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "starting recording RTP session on port %d", spa->rtp->stream[idx]->port);
    }
    if (spa->rtcp->stream[idx]->rrc == NULL && cfsp->rrtcp != 0) {
        rargs.idx = 1;
        spa->rtcp->stream[idx]->rrc = rtpp_record_ctor(cfsp, &rargs, spa, rname, idx, RECORD_RTCP);
        if (spa->rtcp->stream[idx]->rrc == NULL) {
            RTPP_OBJ_DECREF(spa->rtp->stream[idx]->rrc);
            spa->rtp->stream[idx]->rrc = NULL;
            goto out;
        }
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "starting recording RTCP session on port %d", spa->rtcp->stream[idx]->port);
    }
    if (cmd != NULL) {
        if (rop->reply_port != 0 && remote) {
            if (CALL_SMETHOD(cmd->reply, deliver_port_addr, rargs.laddr, rargs.lport) != 0)
                goto out;
        } else {
            CALL_SMETHOD(cmd->reply, deliver_ok);
        }
    }
    rval = 0;
out:
    if (remote) {
        RTPP_OBJ_DECREF(rargs.fds[0]);
        RTPP_OBJ_DECREF(rargs.fds[1]);
    }
    return (rval);
}
