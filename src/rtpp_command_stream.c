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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg.h"
#include "rtpp_defines.h"
#include "rtpp_debug.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_stream.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_stats.h"
#include "rtpp_command_reply.h"
#include "rtpp_network.h"
#include "rtpp_util.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"

static void
rtpp_command_stream_compact(struct rtpp_cmd_connection *rcs)
{
    char *cp;
    int clen;

    if (rcs->inbuf_ppos == 0 || rcs->inbuf_epos == 0)
        return;
    if (rcs->inbuf_ppos == rcs->inbuf_epos) {
        rcs->inbuf_ppos = 0;
        rcs->inbuf_epos = 0;
        return;
    }
    cp = &rcs->inbuf[rcs->inbuf_ppos];
    clen = rcs->inbuf_epos - rcs->inbuf_ppos;
    memmove(rcs->inbuf, cp, clen);
    rcs->inbuf_epos = clen;
    rcs->inbuf_ppos = 0;
}   

int
rtpp_command_stream_doio(const struct rtpp_cfg *cfsp, struct rtpp_cmd_connection *rcs)
{
    int len, blen;
    char *cp;

    rtpp_command_stream_compact(rcs);
    cp = &(rcs->inbuf[rcs->inbuf_epos]);
    blen = sizeof(rcs->inbuf) - rcs->inbuf_epos;

    for (;;) {
        len = read(rcs->controlfd_in, cp, blen);
        if (len != -1 || (errno != EAGAIN && errno != EINTR))
            break;
    }
    if (len == -1) {
        if (errno != EAGAIN && errno != EINTR)
            RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "can't read from control socket");
        return (-1);
    }
    rcs->inbuf_epos += len;
    return (len);
}

#ifndef ECODE_NOMEM_9
# error ECODE_NOMEM_9 is not defined!
#endif
#define ENM_STR "E" STR(ECODE_NOMEM_9)
#define ENM_PSTR ENM_STR "\\n"

static void
rcs_reply_nomem(struct rtpp_log *log, int controlfd, struct rtpp_command_stats *csp)
{
    static const char buf[] = ENM_STR "\n";

    if (write(controlfd, buf, sizeof(buf) - 1) < 0) {
        RTPP_DBG_ASSERT(!IS_WEIRD_ERRNO(errno));
        RTPP_ELOG(log, RTPP_LOG_ERR, "ENOMEM: failure sending \"" ENM_PSTR "\"");
    } else {
        RTPP_LOG(log, RTPP_LOG_ERR, "ENOMEM: sending \"" ENM_PSTR "\"");
        csp->ncmds_repld.cnt++;
    }
    csp->ncmds_errs.cnt++;
}

struct rtpp_command *
rtpp_command_stream_get(const struct rtpp_cfg *cfsp, struct rtpp_cmd_connection *rcs,
  int *rval, const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp)
{
    char *cp, *cp1;
    int len;
    struct rtpp_command *cmd;

    if (rcs->inbuf_epos == rcs->inbuf_ppos) {
        *rval = GET_CMD_EAGAIN;
        return (NULL);
    }
    cp = &(rcs->inbuf[rcs->inbuf_ppos]);
    len = rcs->inbuf_epos - rcs->inbuf_ppos;
    cp1 = memchr(cp, '\n', len);
    if (cp1 == NULL) {
        *rval = GET_CMD_EAGAIN;
        return (NULL);
    }

    len = cp1 - cp;

    cmd = rtpp_command_ctor(cfsp, rcs->controlfd_out, dtime, csp, 0);
    if (cmd == NULL) {
        *rval = GET_CMD_ENOMEM;
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "ENOMEM: command \"%.*s\""
          " could not be processed", len, cp);
        rcs_reply_nomem(cfsp->glog, rcs->controlfd_out, csp);
        rcs->inbuf_ppos += len + 1;
        return (NULL);
    }

    if (rcs->rlen > 0) {
        rtpp_command_set_raddr(cmd, sstosa(&rcs->raddr), rcs->rlen);
    }

    memcpy(cmd->buf, cp, len);
    cmd->buf[len] = '\0';
    rcs->inbuf_ppos += len + 1;

    if (rtpp_command_split(cmd, len, rval, NULL) != 0) {
        /* Error reply is handled by the rtpp_command_split() */
        RTPP_OBJ_DECREF(cmd);
        return (NULL);
    }

    return (cmd);
}
