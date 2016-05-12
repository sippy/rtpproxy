/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-20015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <netinet/in.h>
#include <sys/stat.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rtpa_stats.h"
#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtp.h"
#include "rtpp_analyzer.h"
#include "rtp_resizer.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid_singlet.h"
#include "rtp_info.h"
#include "rtp_packet.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_network.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_record.h"
#include "rtpp_stats.h"
#include "rtpp_stream.h"
#include "rtpp_stream_fin.h"
#include "rtpp_server.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_weakref.h"
#include "rtpp_ttl.h"

struct rtpp_stream_priv
{
    struct rtpp_stream pub;
    struct rtpp_weakref_obj *servers_wrt;
    struct rtpp_stats *rtpp_stats;
    pthread_mutex_t lock;
    /* Weak reference to the "rtpp_server" (player) */
    uint64_t rtps;
    enum rtpp_stream_side side;
    /* Timestamp of the last session update */
    double last_update;
    /* Flag that indicates whether or not address supplied by client can't be trusted */
    int untrusted_addr;
    /* Save previous address when doing update */
    struct sockaddr *prev_addr;
};

#define PUB2PVT(pubp) \
  ((struct rtpp_stream_priv *)((char *)(pubp) - offsetof(struct rtpp_stream_priv, pub)))

static void rtpp_stream_dtor(struct rtpp_stream_priv *);
static int rtpp_stream_handle_play(struct rtpp_stream *, char *, char *,
  int, struct rtpp_command *, int);
static void rtpp_stream_handle_noplay(struct rtpp_stream *);
static int rtpp_stream_isplayer_active(struct rtpp_stream *);
static void rtpp_stream_finish_playback(struct rtpp_stream *, uint64_t);
static const char *rtpp_stream_get_actor(struct rtpp_stream *);
static const char *rtpp_stream_get_proto(struct rtpp_stream *);
static int rtpp_stream_latch(struct rtpp_stream *, double,
  struct rtp_packet *);
static int rtpp_stream_check_latch_override(struct rtpp_stream *,
  struct rtp_packet *);
static void rtpp_stream_fill_addr(struct rtpp_stream *,
  struct rtp_packet *);
static int rtpp_stream_guess_addr(struct rtpp_stream *,
  struct rtp_packet *);
static void rtpp_stream_prefill_addr(struct rtpp_stream *,
  struct sockaddr **, double);
static uint64_t rtpp_stream_get_rtps(struct rtpp_stream *);
static void rtpp_stream_replace_rtps(struct rtpp_stream *, uint64_t, uint64_t);

struct rtpp_stream *
rtpp_stream_ctor(struct rtpp_log *log, struct rtpp_weakref_obj *servers_wrt,
  struct rtpp_stats *rtpp_stats, enum rtpp_stream_side side,
  int session_type, uint64_t seuid)
{
    struct rtpp_stream_priv *pvt;
    struct rtpp_refcnt *rcnt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_stream_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    if (session_type == SESS_RTP) {
        pvt->pub.analyzer = rtpp_analyzer_ctor(log);
        if (pvt->pub.analyzer == NULL) {
            goto e3;
        }
    }
    pvt->pub.pcnt_strm = rtpp_pcnt_strm_ctor();
    if (pvt->pub.pcnt_strm == NULL) {
        goto e4;
    }
    pvt->servers_wrt = servers_wrt;
    pvt->rtpp_stats = rtpp_stats;
    pvt->pub.log = log;
    CALL_METHOD(log->rcnt, incref);
    pvt->side = side;
    pvt->pub.session_type = session_type;
    pvt->pub.handle_play = &rtpp_stream_handle_play;
    pvt->pub.handle_noplay = &rtpp_stream_handle_noplay;
    pvt->pub.isplayer_active = &rtpp_stream_isplayer_active;
    pvt->pub.finish_playback = &rtpp_stream_finish_playback;
    pvt->pub.get_actor = &rtpp_stream_get_actor;
    pvt->pub.get_proto = &rtpp_stream_get_proto;
    pvt->pub.latch = &rtpp_stream_latch;
    pvt->pub.check_latch_override = &rtpp_stream_check_latch_override;
    pvt->pub.fill_addr = &rtpp_stream_fill_addr;
    pvt->pub.prefill_addr = &rtpp_stream_prefill_addr;
    pvt->pub.get_rtps = &rtpp_stream_get_rtps;
    pvt->pub.replace_rtps = &rtpp_stream_replace_rtps;
    if (session_type == SESS_RTCP) {
        pvt->pub.guess_addr = &rtpp_stream_guess_addr;
    }
    rtpp_gen_uid(&pvt->pub.stuid);
    pvt->pub.seuid = seuid;
    CALL_METHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_stream_dtor,
      pvt);
    return (&pvt->pub);

e4:
    if (session_type == SESS_RTP) {
         CALL_METHOD(pvt->pub.analyzer->rcnt, decref);
    }
e3:
    pthread_mutex_destroy(&pvt->lock);
e1:
    CALL_METHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_stream_dtor(struct rtpp_stream_priv *pvt)
{
    struct rtpp_stream *pub;

    pub = &(pvt->pub);
    rtpp_stream_fin(pub);
    if (pub->analyzer != NULL) {
         struct rtpa_stats rst;
         char ssrc_buf[11];
         const char *actor, *ssrc;

         actor = rtpp_stream_get_actor(pub);
         CALL_METHOD(pub->analyzer, get_stats, &rst);
         if (rst.ssrc_changes != 0) {
             snprintf(ssrc_buf, sizeof(ssrc_buf), SSRC_FMT, rst.last_ssrc);
             ssrc = ssrc_buf;
         } else {
             ssrc = "NONE";
         }
         RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO, "RTP stream from %s: "
           "SSRC=%s, ssrc_changes=%u, psent=%u, precvd=%u, plost=%d, pdups=%u",
           actor, ssrc, rst.ssrc_changes, rst.psent, rst.precvd,
           rst.plost, rst.pdups);
         if (rst.psent > 0) {
             CALL_METHOD(pvt->rtpp_stats, updatebyname, "rtpa_nsent", rst.psent);
         }
         if (rst.precvd > 0) {
             CALL_METHOD(pvt->rtpp_stats, updatebyname, "rtpa_nrcvd", rst.precvd);
         }
         if (rst.pdups > 0) {
             CALL_METHOD(pvt->rtpp_stats, updatebyname, "rtpa_ndups", rst.pdups);
         }
         if (rst.pecount > 0) {
             CALL_METHOD(pvt->rtpp_stats, updatebyname, "rtpa_perrs", rst.pecount);
         }
         CALL_METHOD(pvt->pub.analyzer->rcnt, decref);
    }
    if (pub->fd != NULL)
        CALL_METHOD(pub->fd->rcnt, decref);
    if (pub->addr != NULL)
        free(pub->addr);
    if (pvt->prev_addr != NULL)
        free(pvt->prev_addr);
    if (pub->codecs != NULL)
        free(pub->codecs);
    if (pvt->rtps != RTPP_UID_NONE)
        CALL_METHOD(pvt->servers_wrt, unreg, pvt->rtps);
    if (pub->resizer != NULL)
        rtp_resizer_free(pvt->rtpp_stats, pub->resizer);
    if (pub->rrc != NULL)
        CALL_METHOD(pub->rrc->rcnt, decref);
    if (pub->pcount != NULL)
        CALL_METHOD(pub->pcount->rcnt, decref);

    CALL_METHOD(pub->ttl->rcnt, decref);
    CALL_METHOD(pub->pcnt_strm->rcnt, decref);
    CALL_METHOD(pvt->pub.log->rcnt, decref);

    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static void
player_predestroy_cb(struct rtpp_stats *rtpp_stats)
{

    CALL_METHOD(rtpp_stats, updatebyname, "nplrs_destroyed", 1);
}

static int
rtpp_stream_handle_play(struct rtpp_stream *self, char *codecs,
  char *pname, int playcount, struct rtpp_command *cmd, int ptime)
{
    struct rtpp_stream_priv *pvt;
    int n;
    char *cp;
    struct rtpp_server *rsrv;
    uint16_t seq;
    uint32_t ssrc;
    const char *plerror;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    plerror = "reason unknown";
    while (*codecs != '\0') {
        n = strtol(codecs, &cp, 10);
        if (cp == codecs) {
            plerror = "invalid codecs";
            break;
        }
        codecs = cp;
        if (*codecs != '\0')
            codecs++;
        rsrv = rtpp_server_ctor(pname, n, playcount, cmd->dtime, ptime);
        if (rsrv == NULL) {
            RTPP_LOG(pvt->pub.log, RTPP_LOG_DBUG, "rtpp_server_ctor(\"%s\", %d, %d) failed",
              pname, n, playcount);
            plerror = "rtpp_server_ctor() failed";
            continue;
        }
        rsrv->stuid = self->stuid;
        ssrc = CALL_METHOD(rsrv, get_ssrc);
        seq = CALL_METHOD(rsrv, get_seq);
        if (CALL_METHOD(pvt->servers_wrt, reg, rsrv->rcnt, rsrv->sruid) != 0) {
            CALL_METHOD(rsrv->rcnt, decref);
            plerror = "servers_wrt->reg() method failed";
            break;
        }
        assert(pvt->rtps == RTPP_UID_NONE);
        pvt->rtps = rsrv->sruid;
        pthread_mutex_unlock(&pvt->lock);
        cmd->csp->nplrs_created.cnt++;
        CALL_METHOD(rsrv->rcnt, reg_pd, (rtpp_refcnt_dtor_t)player_predestroy_cb,
          pvt->rtpp_stats);
        CALL_METHOD(rsrv->rcnt, decref);
        RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
          "%d times playing prompt %s codec %d: SSRC=" SSRC_FMT ", seq=%u",
          playcount, pname, n, ssrc, seq);
        return 0;
    }
    pthread_mutex_unlock(&pvt->lock);
    RTPP_LOG(pvt->pub.log, RTPP_LOG_ERR, "can't create player: %s", plerror);
    return -1;
}

static void
rtpp_stream_handle_noplay(struct rtpp_stream *self)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->rtps != RTPP_UID_NONE) {
        if (CALL_METHOD(pvt->servers_wrt, unreg, pvt->rtps) != NULL) {
            pvt->rtps = RTPP_UID_NONE;
        }
        RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
          "stopping player at port %d", self->port);
    }
    pthread_mutex_unlock(&pvt->lock);
}

static int
rtpp_stream_isplayer_active(struct rtpp_stream *self)
{
    struct rtpp_stream_priv *pvt;
    int rval;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    rval = (pvt->rtps != RTPP_UID_NONE) ? 1 : 0;
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static void
rtpp_stream_finish_playback(struct rtpp_stream *self, uint64_t sruid)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->rtps != RTPP_UID_NONE && pvt->rtps == sruid) {
        pvt->rtps = RTPP_UID_NONE;
        RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
          "player at port %d has finished", self->port);
    }
    pthread_mutex_unlock(&pvt->lock);
}

static const char *
rtpp_stream_get_actor(struct rtpp_stream *self)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    return ((pvt->side == RTPP_SSIDE_CALLER) ? "caller" : "callee");
}

static const char *
rtpp_stream_get_proto(struct rtpp_stream *self)
{

    return (ST_NAME(self->session_type));
}

static int
rtpp_stream_latch(struct rtpp_stream *self, double dtime,
  struct rtp_packet *packet)
{
    const char *actor, *ptype, *ssrc, *seq, *relatch;
    char ssrc_buf[11], seq_buf[6];
    struct rtpp_stream_priv *pvt;
    char saddr[MAX_AP_STRBUF];

    pvt = PUB2PVT(self);
    if (pvt->last_update != 0 && \
      dtime - pvt->last_update < UPDATE_WINDOW) {
        return (0);
    }

    actor = rtpp_stream_get_actor(self);
    ptype = rtpp_stream_get_proto(self);

    if (self->session_type == SESS_RTP) {
        if (rtp_packet_parse(packet) == RTP_PARSER_OK) {
            self->latch_info.ssrc = packet->parsed->ssrc;
            self->latch_info.seq = packet->parsed->seq;
            snprintf(ssrc_buf, sizeof(ssrc_buf), SSRC_FMT, packet->parsed->ssrc);
            snprintf(seq_buf, sizeof(seq_buf), "%u", packet->parsed->seq);
            ssrc = ssrc_buf;
            seq = seq_buf;
        } else {
            self->latch_info.ssrc = 0;
            ssrc = seq = "INVALID";
        }
    } else {
        self->latch_info.ssrc = 0;
        ssrc = seq = "UNKNOWN";
    }

    addrport2char_r(sstosa(&packet->raddr), saddr, sizeof(saddr));
    if (self->latch_info.latched == 0) {
        relatch = "";
    } else {
        relatch = "re-";
    }
    RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
      "%s's address %slatched in: %s (%s), SSRC=%s, Seq=%s", actor, relatch,
      saddr, ptype, ssrc, seq);
    self->latch_info.latched = 1;
    return (1);
}

static int
rtpp_stream_check_latch_override(struct rtpp_stream *self,
  struct rtp_packet *packet)
{
    const char *actor;
    struct rtpp_stream_priv *pvt;
    char saddr[MAX_AP_STRBUF];

    pvt = PUB2PVT(self);

    if (self->session_type == SESS_RTCP || self->latch_info.ssrc == 0)
        return (0);
    if (rtp_packet_parse(packet) != RTP_PARSER_OK)
        return (0);
    if (packet->parsed->ssrc != self->latch_info.ssrc)
        return (0);
    if (packet->parsed->seq < self->latch_info.seq && self->latch_info.seq - packet->parsed->seq < 536)
        return (0);

    actor = rtpp_stream_get_actor(self);

    addrport2char_r(sstosa(&packet->raddr), saddr, sizeof(saddr));
    RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
      "%s's address re-latched: %s (%s), SSRC=" SSRC_FMT ", Seq=%u->%u", actor,
      saddr, "RTP", self->latch_info.ssrc, self->latch_info.seq,
      packet->parsed->seq);

    self->latch_info.seq = packet->parsed->seq;
    return (1);
}

static void
rtpp_stream_fill_addr(struct rtpp_stream *self,
  struct rtp_packet *packet)
{
    const char *actor, *ptype;
    struct rtpp_stream_priv *pvt;
    char saddr[MAX_AP_STRBUF];

    pvt = PUB2PVT(self);

    pvt->untrusted_addr = 1;
    memcpy(self->addr, &packet->raddr, packet->rlen);
    if (pvt->prev_addr == NULL || memcmp(pvt->prev_addr,
      &packet->raddr, packet->rlen) != 0) {
        self->latch_info.latched = 1;
    }

    actor = rtpp_stream_get_actor(self);
    ptype =  rtpp_stream_get_proto(self);
    addrport2char_r(sstosa(&packet->raddr), saddr, sizeof(saddr));
    RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO,
      "%s's address filled in: %s (%s)", actor, saddr, ptype);
    return;
}

static int
rtpp_stream_guess_addr(struct rtpp_stream *self,
  struct rtp_packet *packet)
{
    int rport;
    const char *actor, *ptype;
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);

    if (self->addr != NULL && ishostseq(self->addr, sstosa(&packet->raddr))) {
        return (0);
    }
    if (self->addr == NULL) {
        self->addr = malloc(packet->rlen);
        if (self->addr == NULL) {
            return (-1);
        }
    }
    actor = rtpp_stream_get_actor(self);
    ptype =  rtpp_stream_get_proto(self);
    rport = ntohs(satosin(&packet->raddr)->sin_port);
    if (IS_LAST_PORT(rport)) {
        return (-1);
    }
    memcpy(self->addr, &packet->raddr, packet->rlen);
    satosin(self->addr)->sin_port = htons(rport + 1);
    /* Use guessed value as the only true one for asymmetric clients */
    self->latch_info.latched = self->asymmetric;
    RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO, "guessing %s port "
      "for %s to be %d", ptype, actor, rport + 1);

    return (0);
}

static void
rtpp_stream_prefill_addr(struct rtpp_stream *self, struct sockaddr **iapp,
  double dtime)
{
    struct rtpp_stream_priv *pvt;
    char saddr[MAX_AP_STRBUF];
    const char *actor, *ptype;

    pvt = PUB2PVT(self);

    if (self->addr != NULL)
        pvt->last_update = dtime;

    /*
     * Unless the address provided by client historically
     * cannot be trusted and address is different from one
     * that we recorded update it.
     */
    if (pvt->untrusted_addr != 0)
        return;
    if (self->addr != NULL && isaddrseq(self->addr, *iapp)) {
        return;
    }

    addrport2char_r(*iapp, saddr, sizeof(saddr));
    actor = rtpp_stream_get_actor(self);
    ptype =  rtpp_stream_get_proto(self);
    RTPP_LOG(pvt->pub.log, RTPP_LOG_INFO, "pre-filling %s's %s address "
      "with %s", actor, ptype, saddr);
    if (self->addr != NULL) {
        if (self->latch_info.latched != 0) {
            if (pvt->prev_addr != NULL)
                 free(pvt->prev_addr);
            pvt->prev_addr = self->addr;
        } else {
            free(self->addr);
        }
    }
    self->addr = *iapp;
    *iapp = NULL;
}

static uint64_t
rtpp_stream_get_rtps(struct rtpp_stream *self)
{
    struct rtpp_stream_priv *pvt;
    uint64_t rval;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    rval = pvt->rtps;
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}
static void
rtpp_stream_replace_rtps(struct rtpp_stream *self, uint64_t rtps_old,
  uint64_t rtps_new)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->rtps == rtps_old) {
        pvt->rtps = rtps_new;
    }
    pthread_mutex_unlock(&pvt->lock);
}
