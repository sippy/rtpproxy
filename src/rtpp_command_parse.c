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
#include <stdint.h>
#include <stdlib.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_command.h"
#include "rtpp_command_parse.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "commands/rpcpv1_query.h"
#include "rtpp_command_reply.h"
#include "rtpp_stats.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_reply.h"

struct cmd_props {
    int max_argc;
    int min_argc;
    int has_cmods;
    int has_call_id;
    int has_subc;
    int fpos;
    int tpos;
    const char *cmods;
};

static int 
fill_cmd_props(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  struct cmd_props *cpp)
{

    cpp->has_call_id = 1;
    cpp->has_subc = 0;
    cpp->fpos = -1;
    cpp->tpos = -1;
    cpp->cmods = &(cmd->args.v[0].s[1]);
    switch (cmd->args.v[0].s[0]) {
    case 'u':
    case 'U':
        cmd->cca.op = UPDATE;
        cmd->cca.rname = "update/create";
        cmd->cca.hint = "U[opts] callid remote_ip remote_port from_tag [to_tag] [notify_socket notify_tag]";
        cpp->max_argc = 8;
        cpp->min_argc = 5;
        cpp->has_cmods = 1;
        cpp->fpos = 4;
        cpp->tpos = 5;
        cpp->has_subc = 1;
        break;

    case 'l':
    case 'L':
        cmd->cca.op = LOOKUP;
        cmd->cca.rname = "lookup";
        cmd->cca.hint = "L[opts] callid remote_ip remote_port from_tag [to_tag]";
        cpp->max_argc = 6;
        cpp->min_argc = 5;
        cpp->has_cmods = 1;
        cpp->fpos = 4;
        cpp->tpos = 5;
        cpp->has_subc = 1;
        break;

    case 'd':
    case 'D':
        cmd->cca.op = DELETE;
        cmd->cca.rname = "delete";
        cmd->cca.hint = "D[w] callid from_tag [to_tag]";
        cpp->max_argc = 4;
        cpp->min_argc = 3;
        cpp->has_cmods = 1;
        cpp->fpos = 2;
        cpp->tpos = 3;
        break;

    case 'p':
    case 'P':
        cmd->cca.op = PLAY;
        cmd->cca.rname = "play";
        cmd->cca.hint = "P[n] callid pname codecs from_tag [to_tag]";
        cpp->max_argc = 6;
        cpp->min_argc = 5;
        cpp->has_cmods = 1;
        cpp->fpos = 4;
        cpp->tpos = 5;
        break;

    case 'r':
    case 'R':
        cmd->cca.op = RECORD;
        cmd->cca.rname = "record";
        if (cfsp->record_pcap != 0) {
            cmd->cca.hint = "R[s] call_id from_tag [to_tag]";
        } else {
            cmd->cca.hint = "R call_id from_tag [to_tag]";
        }
        cpp->max_argc = 4;
        cpp->min_argc = 3;
        cpp->has_cmods = 1;
        cpp->fpos = 2;
        cpp->tpos = 3;
        break;

    case 'c':
    case 'C':
        cmd->cca.op = COPY;
        cmd->cca.rname = "copy";
        cmd->cca.hint = "C[-xxx-] call_id -XXX- from_tag [to_tag]";
        cpp->max_argc = 5;
        cpp->min_argc = 4;
        cpp->has_cmods = 1;
        cpp->fpos = 3;
        cpp->tpos = 4;
        break;

    case 's':
    case 'S':
        cmd->cca.op = NOPLAY;
        cmd->cca.rname = "noplay";
        cmd->cca.hint = "S call_id from_tag [to_tag]";
        cpp->max_argc = 4;
        cpp->min_argc = 3;
        cpp->has_cmods = 0;
        cpp->fpos = 2;
        cpp->tpos = 3;
        break;

    case 'n':
    case 'N':
        cmd->cca.op = NORECORD;
        cmd->cca.rname = "norecord";
        cmd->cca.hint = "N[a] call_id from_tag [to_tag]";
        cpp->max_argc = 4;
        cpp->min_argc = 3;
        cpp->has_cmods = 1;
        cpp->fpos = 2;
        cpp->tpos = 3;
        break;

    case 'v':
    case 'V':
        if (cpp->cmods[0] == 'F' || cpp->cmods[0] == 'f') {
            cpp->cmods += 1;
            cmd->cca.op = VER_FEATURE;
            cmd->cca.rname = "feature_check";
            cmd->cca.hint = "VF feature_num";
            cmd->no_glock = 1;
            cpp->max_argc = 2;
            cpp->min_argc = 2;
            cpp->has_cmods = 0;
            cpp->has_call_id = 0;
            break;
        }
        cmd->cca.op = GET_VER;
        cmd->cca.rname = "get_version";
        cmd->cca.hint = "V";
        cmd->no_glock = 1;
        cpp->max_argc = 1;
        cpp->min_argc = 1;
        cpp->has_cmods = 0;
        cpp->has_call_id = 0;
        break;

    case 'i':
    case 'I':
        cmd->cca.op = INFO;
        cmd->cca.rname = "get_info";
        cmd->cca.hint = "I[b]";
        cpp->max_argc = 1;
        cpp->min_argc = 1;
        cpp->has_cmods = 1;
        cpp->has_call_id = 0;
        break;

    case 'q':
    case 'Q':
        cmd->cca.op = QUERY;
        cmd->cca.rname = "query";
        cmd->cca.hint = "Q[v] call_id from_tag [to_tag [stat_name1 ...[stat_nameN]]]";
        cpp->max_argc = 4 + RTPP_QUERY_NSTATS;
        cpp->min_argc = 3;
        cpp->has_cmods = 1;
        cpp->fpos = 2;
        cpp->tpos = 3;
        cpp->has_subc = 1;
        break;

    case 'x':
    case 'X':
        cmd->cca.op = DELETE_ALL;
        cmd->cca.rname = "delete_all";
        cmd->cca.hint = "X";
        cpp->max_argc = 1;
        cpp->min_argc = 1;
        cpp->has_cmods = 0;
        cpp->has_call_id = 0;
        break;

    case 'g':
    case 'G':
        cmd->cca.op = GET_STATS;
        cmd->cca.rname = "get_stats";
        cmd->cca.hint = "G[v] [stat_name1 [stat_name2 [stat_name3 ...[stat_nameN]]]]";
        cmd->no_glock = 1;
        cpp->max_argc = CALL_SMETHOD(cfsp->rtpp_stats, getnstats) + 1;
        cpp->min_argc = 1;
        cpp->has_cmods = 1;
        cpp->has_call_id = 0;
        break;

    default:
        return (-1);
    }
    return (0);
}

int
rtpp_command_pre_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    struct cmd_props cprops = {};

    if (fill_cmd_props(cfsp, cmd, &cprops) != 0) {
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "unknown command \"%c\"",
          cmd->args.v[0].s[0]);
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_CMDUNKN);
        return (-1);
    }
    if (cmd->args.c < cprops.min_argc || cmd->args.c > cprops.max_argc) {
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "%s command syntax error"
          ": invalid number of arguments (%d)", cmd->cca.rname, cmd->args.c);
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_NARGS);
        return (-1);
    }
    if (cprops.has_cmods == 0 && cprops.cmods[0] != '\0') {
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "%s command syntax error"
          ": modifiers are not supported by the command", cmd->cca.rname);
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_MODS);
        return (-1);
    }
    if (cprops.has_subc == 0 && cmd->subc.n > 0) {
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "%s command syntax error"
          ": subcommand is not supported", cmd->cca.rname);
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_SUBC);
        return (-1);
    }
    if (cprops.has_call_id) {
        cmd->cca.call_id = rtpp_str_fix(&cmd->args.v[1]);
    }
    if (cprops.fpos > 0) {
        cmd->cca.from_tag = rtpp_str_fix(&cmd->args.v[cprops.fpos]);
    }
    if (cprops.tpos > 0) {
        cmd->cca.to_tag = rtpp_str_fix(&cmd->args.v[cprops.tpos]);
    }
    return (0);
}
