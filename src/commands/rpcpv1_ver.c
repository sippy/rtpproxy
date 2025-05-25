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

#include "config_pp.h"

#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_reply.h"
#include "commands/rpcpv1_ver.h"
#include "rtpp_tnotify_set.h"

const static struct proto_cap proto_caps[] = {
    /*
     * The first entry must be basic protocol version and isn't shown
     * as extension on -v.
     */
    { "20040107", "Basic RTP proxy functionality" },
    { "20050322", "Support for multiple RTP streams and MOH" },
    { "20060704", "Support for extra parameter in the V command" },
    { "20071116", "Support for RTP re-packetization" },
    { "20071218", "Support for forking (copying) RTP stream" },
    { "20080403", "Support for RTP statistics querying" },
    { "20081102", "Support for setting codecs in the update/lookup command" },
    { "20081224", "Support for session timeout notifications" },
    { "20090810", "Support for automatic bridging" },
    { "20140323", "Support for tracking/reporting load" },
    { "20140617", "Support for anchoring session connect time" },
    { "20141004", "Support for extendable performance counters" },
    { "20150330", "Support for allocating a new port (\"Un\"/\"Ln\" commands)" },
    { "20150420", "Support for SEQ tracking and new rtpa_ counters; Q command extended" },
    { "20150617", "Support for the wildcard %%CC_SELF%% as a disconnect notify target" },
    { "20191015", "Support for the && sub-command specifier" },
    { "20200226", "Support for the N command to stop recording" },
    { "20230205", "Support for \"rtpa_nlost\" counter; extend catch_dtmf module with \"h\" modifier" },
    { "20230314", "Support for for \"fusing\" G and D commands" },
    { "20230424", "Support for for \"longest_ipi\", \"rtpa_jlast\", \"rtpa_jmax\" and \"rtpa_javg\" counters" },
    { "20250523", "Support for the \"P\" modifier in the C command"},
    { NULL, NULL }
};

void
handle_ver_feature(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    int i, known;

    /*
     * Wait for protocol version datestamp and check whether we
     * know it.
     */
    /*
     * Only list 20081224 protocol mod as supported if
     * user actually enabled notification with -n
     */
    if (strcmp(cmd->args.v[1].s, "20081224") == 0 &&
      !CALL_METHOD(cfsp->rtpp_tnset_cf, isenabled)) {
        CALL_SMETHOD(cmd->reply, deliver_number, 0);
        return;
    }
    for (known = i = 0; proto_caps[i].pc_id != NULL; ++i) {
        if (!strcmp(cmd->args.v[1].s, proto_caps[i].pc_id)) {
            known = 1;
            break;
        }
    }
    CALL_SMETHOD(cmd->reply, deliver_number, known);
}

const struct proto_cap *
iterate_proto_caps(const struct proto_cap *prevp)
{
    int i;

    if (prevp == NULL) {
        return (&proto_caps[0]);
    }
    for (i = 0; proto_caps[i].pc_id != NULL; i++) {
        if (&proto_caps[i] == prevp) {
            if (proto_caps[i + 1].pc_id != NULL)
                return (&proto_caps[i + 1]);
            return (NULL);
        }
    }
    abort();
}
