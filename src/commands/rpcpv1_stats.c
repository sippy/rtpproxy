/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_command.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_stats.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_reply.h"

#define CHECK_OVERFLOW() \
    if (aerr != 0) { \
        RTPP_LOG(cmd->glog, RTPP_LOG_ERR, \
          "STATS: output buffer overflow"); \
        return (ECODE_RTOOBIG_1); \
    }

int
handle_get_stats(struct rtpp_stats *rsp, struct rtpp_command *cmd, int verbose)
{
    int aerr = 0, i;

    for (i = 1; i < cmd->args.c && aerr == 0; i++) {
        if (i > 1) {
            CHECK_OVERFLOW();
            aerr = CALL_SMETHOD(cmd->reply, appendf, " ");
        }
        if (verbose != 0) {
            CHECK_OVERFLOW();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%.*s=", \
              FMTSTR(&cmd->args.v[i]));
        }
        CHECK_OVERFLOW();
        aerr = CALL_SMETHOD(rsp, nstr, cmd->args.v[i].s, cmd->reply);
        if (aerr != 0) {
            return (ECODE_STSFAIL);
        }
    }
    CHECK_OVERFLOW();
    assert(CALL_SMETHOD(cmd->reply, append, "\n", 2, 1) == 0);
    CALL_SMETHOD(cmd->reply, commit);
    CALL_SMETHOD(cmd->reply, deliver, 0);
    return (0);
}
