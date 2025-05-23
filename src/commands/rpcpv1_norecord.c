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
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_defines.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_pipe.h"
#include "rtpp_record.h"
#include "rtpp_stream.h"
#include "rtpp_hash_table.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "commands/rpcpv1_norecord.h"


struct norecord_ematch_arg {
    int nrecorded;
    int all;
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
    const struct rtpp_cfg *cfsp;
};

static int
handle_stop_record(const struct rtpp_cfg *cfsp, struct rtpp_session *spa, int idx)
{
	if (spa->rtp->stream[idx]->rrc == NULL)
		return (-1);
	if (cfsp->rrtcp != 0) {
		assert(spa->rtcp->stream[idx]->rrc != NULL);
		RTPP_LOG(spa->log, RTPP_LOG_INFO,
				"stopping recording RTCP session on port %d", spa->rtcp->stream[idx]->port);
		RTPP_OBJ_DECREF(spa->rtcp->stream[idx]->rrc);
		spa->rtcp->stream[idx]->rrc = NULL;
	}
	RTPP_LOG(spa->log, RTPP_LOG_INFO,
			"stopping recording RTP session on port %d", spa->rtp->stream[idx]->port);
	RTPP_OBJ_DECREF(spa->rtp->stream[idx]->rrc);
	spa->rtp->stream[idx]->rrc = NULL;
	return 0;
}

static int
rtpp_cmd_norecord_ematch(void *dp, void *ap)
{
    struct rtpp_session *spa;
    int idx;
    struct norecord_ematch_arg *rep;

    spa = (struct rtpp_session *)dp;
    rep = (struct norecord_ematch_arg *)ap;

    if (compare_session_tags(spa->from_tag, rep->from_tag, NULL) != 0) {
        idx = 1;
    } else if (rep->to_tag != NULL &&
      (compare_session_tags(spa->from_tag, rep->to_tag, NULL)) != 0) {
        idx = 0;
    } else {
        return(RTPP_HT_MATCH_CONT);
    }
    if (handle_stop_record(rep->cfsp, spa, idx) == 0) {
        rep->nrecorded++;
    }
    if (rep->all && handle_stop_record(rep->cfsp, spa, NOT(idx)) == 0) {
        rep->nrecorded++;
    }
    return(RTPP_HT_MATCH_CONT);
}

int
handle_norecord(const struct rtpp_cfg *cfsp, struct common_cmd_args *ccap, int all)
{
    struct norecord_ematch_arg rea;

    memset(&rea, '\0', sizeof(rea));
    rea.from_tag = ccap->from_tag;
    rea.to_tag = ccap->to_tag;
    rea.cfsp = cfsp;
    rea.all = all;
    CALL_SMETHOD(cfsp->sessions_ht, foreach_key_str, ccap->call_id,
      rtpp_cmd_norecord_ematch, &rea);
    if (rea.nrecorded == 0) {
        return -1;
    }
    return 0;
}
