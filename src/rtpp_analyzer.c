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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtp_analyze.h"
#include "rtpp_analyzer.h"
#include "rtpp_mallocs.h"

struct rtpp_analyzer_priv {
    struct rtpp_analyzer pub;
    struct rtpp_session_stat rstat;
    uint32_t pecount;
    uint32_t aecount;
    struct rtpp_log *log;
};

static enum update_rtpp_stats_rval rtpp_analyzer_update(struct rtpp_analyzer *,
  struct rtp_packet *);
static void rtpp_analyzer_get_stats(struct rtpp_analyzer *,
  struct rtpa_stats *);
static int rtpp_analyzer_get_jstats(struct rtpp_analyzer *,
  struct rtpa_stats_jitter *);
static void rtpp_analyzer_dtor(struct rtpp_analyzer_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_analyzer_priv *)((char *)(pubp) - offsetof(struct rtpp_analyzer_priv, pub)))

struct rtpp_analyzer *
rtpp_analyzer_ctor(struct rtpp_log *log)
{
    struct rtpp_analyzer_priv *pvt;
    struct rtpp_analyzer *rap;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_analyzer_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    rap = &pvt->pub;
    if (rtpp_stats_init(&pvt->rstat) != 0) {
        goto e0;
    }
    pvt->log = log;
    rap->update = &rtpp_analyzer_update;
    rap->get_stats = &rtpp_analyzer_get_stats;
    rap->get_jstats = &rtpp_analyzer_get_jstats;
    CALL_SMETHOD(log->rcnt, incref);
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_analyzer_dtor,
      pvt);
    return (rap);
e0:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
    return (NULL);
}

static enum update_rtpp_stats_rval
rtpp_analyzer_update(struct rtpp_analyzer *rap, struct rtp_packet *pkt)
{
    struct rtpp_analyzer_priv *pvt;
    enum update_rtpp_stats_rval rval;

    pvt = PUB2PVT(rap);
    if (rtp_packet_parse(pkt) != RTP_PARSER_OK) {
        pvt->pecount++;
        return (UPDATE_ERR);
    }
    rval = update_rtpp_stats(pvt->log, &(pvt->rstat), &(pkt->data.header),
      pkt->parsed, pkt->rtime.mono);
    if (rval == UPDATE_ERR) {
        pvt->aecount++;
    }
    pvt->rstat.last.pt = pkt->data.header.pt;
    return (rval);
}

static void
rtpp_analyzer_get_stats(struct rtpp_analyzer *rap, struct rtpa_stats *rsp)
{
    struct rtpp_session_stat ostat;
    struct rtpp_analyzer_priv *pvt;

    pvt = PUB2PVT(rap);
    rsp->pecount = pvt->pecount;
    rsp->aecount = pvt->aecount;
    memset(&ostat, '\0', sizeof(ostat));
    update_rtpp_totals(&(pvt->rstat), &ostat);
    rsp->psent = ostat.psent;
    rsp->precvd = ostat.precvd;
    rsp->pdups = ostat.duplicates;
    rsp->ssrc_changes = pvt->rstat.ssrc_changes;
    rsp->last_ssrc = pvt->rstat.last.ssrc;
    rsp->plost = ostat.psent - ostat.precvd;
    if (pvt->rstat.last.pt != PT_UNKN) {
        rsp->last_pt = pvt->rstat.last.pt;
    } else {
        rsp->last_pt = -1;
    }
}

static int
rtpp_analyzer_get_jstats(struct rtpp_analyzer *rap,
  struct rtpa_stats_jitter *jrsp)
{
    struct rtpp_analyzer_priv *pvt;
    int rval;

    pvt = PUB2PVT(rap);
    rval = get_jitter_stats(pvt->rstat.jdata, jrsp, pvt->log);
    return (rval);
}

static void
rtpp_analyzer_dtor(struct rtpp_analyzer_priv *pvt)
{

    rtpp_stats_destroy(&pvt->rstat);
    CALL_SMETHOD(pvt->log->rcnt, decref);
    free(pvt);
}
