/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_types.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtp_analyze.h"
#include "rtpp_analyzer.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

struct rtpp_analyzer {
    struct rtpp_session_stat rstat;
    uint32_t pecount;
    uint32_t aecount;
};

struct rtpp_analyzer *
rtpp_analyzer_ctor(void)
{
    struct rtpp_analyzer *rap;

    rap = rtpp_zmalloc(sizeof(struct rtpp_analyzer));
    if (rap == NULL) {
        return (NULL);
    }
    return (rap);
}

int
rtpp_analyzer_update(struct rtpp_session_obj *sp, struct rtpp_analyzer *rap,
  struct rtp_packet *pkt)
{

    if (rtp_packet_parse(pkt) != RTP_PARSER_OK) {
        rap->pecount++;
        return (-1);
    }
    if (update_rtpp_stats(sp->log, &(rap->rstat), &(pkt->data.header), pkt->parsed, pkt->rtime) != 0) {
        rap->aecount++;
        return (-1);
    }
    return (0);
}

void
rtpp_analyzer_stat(struct rtpp_analyzer *rap, struct rtpp_analyzer_stats *rsp)
{
    struct rtpp_session_stat ostat;

    rsp->pecount = rap->pecount;
    rsp->aecount = rap->aecount;
    memset(&ostat, '\0', sizeof(ostat));
    update_rtpp_totals(&(rap->rstat), &ostat);
    rsp->psent = ostat.psent;
    rsp->precvd = ostat.precvd;
    rsp->pdups = ostat.duplicates;
    rsp->ssrc_changes = rap->rstat.ssrc_changes;
    rsp->last_ssrc = rap->rstat.last.ssrc;
}

void
rtpp_analyzer_dtor(struct rtpp_analyzer *rap)
{

    free(rap);
}
