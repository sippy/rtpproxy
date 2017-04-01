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
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_pipe.h"
#include "rtpp_record.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

int
handle_copy(struct cfg *cf, struct rtpp_session *spa, int idx, char *rname,
  int record_single_file)
{
    int remote;

    remote = (rname != NULL && strncmp("udp:", rname, 4) == 0)? 1 : 0;

    if (remote == 0 && record_single_file != 0) {
        if (spa->rtp->stream[idx]->rrc != NULL)
            return (-1);
        if (spa->rtp->stream[NOT(idx)]->rrc != NULL) {
            CALL_SMETHOD(spa->rtp->stream[NOT(idx)]->rrc->rcnt, incref);
            spa->rtp->stream[idx]->rrc = spa->rtp->stream[NOT(idx)]->rrc;
        } else {
            spa->rtp->stream[idx]->rrc = rtpp_record_open(cf, spa, rname, idx, RECORD_BOTH);
            if (spa->rtp->stream[idx]->rrc == NULL) {
                return (-1);
            }
            RTPP_LOG(spa->log, RTPP_LOG_INFO,
              "starting recording RTP session on port %d", spa->rtp->stream[idx]->port);
        }
        assert(spa->rtcp->stream[idx]->rrc == NULL);
        if (cf->stable->rrtcp != 0) {
            CALL_SMETHOD(spa->rtp->stream[idx]->rrc->rcnt, incref);
            spa->rtcp->stream[idx]->rrc = spa->rtp->stream[idx]->rrc;
            RTPP_LOG(spa->log, RTPP_LOG_INFO,
              "starting recording RTCP session on port %d", spa->rtcp->stream[idx]->port);
        }
        return (0);
    }

    if (spa->rtp->stream[idx]->rrc == NULL) {
        spa->rtp->stream[idx]->rrc = rtpp_record_open(cf, spa, rname, idx, RECORD_RTP);
        if (spa->rtp->stream[idx]->rrc == NULL) {
            return (-1);
        }
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "starting recording RTP session on port %d", spa->rtp->stream[idx]->port);
    }
    if (spa->rtcp->stream[idx]->rrc == NULL && cf->stable->rrtcp != 0) {
        spa->rtcp->stream[idx]->rrc = rtpp_record_open(cf, spa, rname, idx, RECORD_RTCP);
        if (spa->rtcp->stream[idx]->rrc == NULL) {
            return (-1);
        }
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "starting recording RTCP session on port %d", spa->rtcp->stream[idx]->port);
    }
    return (0);
}
