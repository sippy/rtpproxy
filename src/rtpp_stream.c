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

#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtp.h"
#include "rtp_resizer.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_refcnt.h"
#include "rtpp_stats.h"
#include "rtpp_stream.h"
#include "rtpp_server.h"
#include "rtpp_util.h"
#include "rtpp_weakref.h"

struct rtpp_stream_priv
{
    struct rtpp_stream_obj pub;
    struct rtpp_weakref_obj *servers_wrt;
    struct rtpp_stats_obj *rtpp_stats;
    struct rtpp_log_obj *log;
    pthread_mutex_t lock;
    /* Weak reference to the "rtpp_server" (player) */
    uint64_t rtps;
    void *rco[0];
};

#define PUB2PVT(pubp) \
  ((struct rtpp_stream_priv *)((char *)(pubp) - offsetof(struct rtpp_stream_priv, pub)))

static void rtpp_stream_dtor(struct rtpp_stream_priv *);
static int rtpp_stream_handle_play(struct rtpp_stream_obj *, char *, char *,
  int, struct rtpp_command *, int);
static void rtpp_stream_handle_noplay(struct rtpp_stream_obj *);
static int rtpp_stream_isplayer_active(struct rtpp_stream_obj *);
static void rtpp_stream_finish_playback(struct rtpp_stream_obj *, uint64_t);

struct rtpp_stream_obj *
rtpp_stream_ctor(struct rtpp_log_obj *log, struct rtpp_weakref_obj *servers_wrt,
  struct rtpp_stats_obj *rtpp_stats)
{
    struct rtpp_stream_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_stream_priv) +
      rtpp_refcnt_osize());
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->pub.rcnt = rtpp_refcnt_ctor_pa(&pvt->rco[0], pvt,
      (rtpp_refcnt_dtor_t)&rtpp_stream_dtor);
    if (pvt->pub.rcnt == NULL) {
        goto e2;
    }
    pvt->servers_wrt = servers_wrt;
    pvt->rtpp_stats = rtpp_stats;
    pvt->log = log;
    CALL_METHOD(log->rcnt, incref);
    pvt->pub.handle_play = &rtpp_stream_handle_play;
    pvt->pub.handle_noplay = &rtpp_stream_handle_noplay;
    pvt->pub.isplayer_active = &rtpp_stream_isplayer_active;
    pvt->pub.finish_playback = &rtpp_stream_finish_playback;
    rtpp_gen_uid(&pvt->pub.stuid);
    return (&pvt->pub);

e2:
    pthread_mutex_destroy(&pvt->lock);
e1:
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_stream_dtor(struct rtpp_stream_priv *pvt)
{
    struct rtpp_stream_obj *pub;

    pub = &(pvt->pub);
    if (pub->addr != NULL)
        free(pub->addr);
    if (pub->prev_addr != NULL)
        free(pub->prev_addr);
    if (pub->codecs != NULL)
        free(pub->codecs);
    if (pvt->rtps != RTPP_UID_NONE)
        CALL_METHOD(pvt->servers_wrt, unreg, pvt->rtps);
    if (pub->resizer != NULL)
        rtp_resizer_free(pvt->rtpp_stats, pub->resizer);

    CALL_METHOD(pvt->log->rcnt, decref);
    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static void
player_predestroy_cb(struct rtpp_stats_obj *rtpp_stats)
{

    CALL_METHOD(rtpp_stats, updatebyname, "nplrs_destroyed", 1);
}

static int
rtpp_stream_handle_play(struct rtpp_stream_obj *self, char *codecs,
  char *pname, int playcount, struct rtpp_command *cmd, int ptime)
{
    struct rtpp_stream_priv *pvt;
    int n;
    char *cp;
    struct rtpp_server_obj *rsrv;
    uint16_t seq;
    uint32_t ssrc;

    pvt = PUB2PVT(self);
    while (*codecs != '\0') {
        n = strtol(codecs, &cp, 10);
        if (cp == codecs)
            break;
        codecs = cp;
        if (*codecs != '\0')
            codecs++;
        rsrv = rtpp_server_ctor(pname, n, playcount, cmd->dtime, ptime);
        if (rsrv == NULL)
            continue;
        rsrv->stuid = self->stuid;
        ssrc = CALL_METHOD(rsrv, get_ssrc);
        seq = CALL_METHOD(rsrv, get_seq);
        if (CALL_METHOD(pvt->servers_wrt, reg, rsrv->rcnt, rsrv->sruid) != 0) {
            CALL_METHOD(rsrv->rcnt, decref);
            break;
        }
        assert(pvt->rtps == RTPP_UID_NONE);
        pvt->rtps = rsrv->sruid;
        cmd->csp->nplrs_created.cnt++;
        CALL_METHOD(rsrv->rcnt, reg_pd, (rtpp_refcnt_dtor_t)player_predestroy_cb,
          pvt->rtpp_stats);
        CALL_METHOD(rsrv->rcnt, decref);
        RTPP_LOG(pvt->log, RTPP_LOG_INFO,
          "%d times playing prompt %s codec %d: SSRC=0x%.8X, seq=%u",
          playcount, pname, n, ssrc, seq);
        return 0;
    }
    RTPP_LOG(pvt->log, RTPP_LOG_ERR, "can't create player");
    return -1;
}

static void
rtpp_stream_handle_noplay(struct rtpp_stream_obj *self)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->rtps != RTPP_UID_NONE) {
        if (CALL_METHOD(pvt->servers_wrt, unreg, pvt->rtps) != NULL) {
            pvt->rtps = RTPP_UID_NONE;
        }
        RTPP_LOG(pvt->log, RTPP_LOG_INFO,
          "stopping player at port %d", self->port);
    }
    pthread_mutex_unlock(&pvt->lock);
}

static int
rtpp_stream_isplayer_active(struct rtpp_stream_obj *self)
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
rtpp_stream_finish_playback(struct rtpp_stream_obj *self, uint64_t sruid)
{
    struct rtpp_stream_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->rtps != RTPP_UID_NONE && pvt->rtps == sruid) {
        pvt->rtps = RTPP_UID_NONE;
        RTPP_LOG(pvt->log, RTPP_LOG_INFO,
          "player at port %d has finished", self->port);
    }
    pthread_mutex_unlock(&pvt->lock);
}
