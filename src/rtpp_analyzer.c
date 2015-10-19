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

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtp_analyze.h"
#include "rtpp_analyzer.h"
#include "rtpp_util.h"

struct rtpp_analyzer {
    struct rtpp_session_stat rstat;
    uint32_t pecount;
    uint32_t aecount;
    struct rtpp_log_obj *log;
};

struct rtpp_analyzer *
rtpp_analyzer_ctor(struct rtpp_log_obj *log)
{
    struct rtpp_analyzer *rap;

    rap = rtpp_zmalloc(sizeof(struct rtpp_analyzer));
    if (rap == NULL) {
        return (NULL);
    }
    rap->log = log;
    CALL_METHOD(log->rcnt, incref);
    return (rap);
}

enum update_rtpp_stats_rval
rtpp_analyzer_update(struct rtpp_analyzer *rap, struct rtp_packet *pkt)
{
    enum update_rtpp_stats_rval rval;

    if (rtp_packet_parse(pkt) != RTP_PARSER_OK) {
        rap->pecount++;
        return (UPDATE_ERR);
    }
    rval = update_rtpp_stats(rap->log, &(rap->rstat), &(pkt->data.header), pkt->parsed, pkt->rtime);
    if (rval == UPDATE_ERR) {
        rap->aecount++;
    }
    return (rval);
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

    CALL_METHOD(rap->log->rcnt, decref);
    free(rap);
}
