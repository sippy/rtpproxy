/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/stat.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_sessinfo.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_util.h"

static void rtpp_sinfo_append(struct rtpp_sessinfo_obj *, struct rtpp_session_obj *,
  int index);
static void rtpp_sinfo_update(struct rtpp_sessinfo_obj *, struct rtpp_session_obj *,
  int, struct rtpp_socket **);
static void rtpp_sinfo_remove(struct rtpp_sessinfo_obj *, struct rtpp_session_obj *,
  int);
static int rtpp_sinfo_copy_polltbl(struct rtpp_sessinfo_obj *, struct rtpp_polltbl *,
  int session_type);

struct rtpp_sessinfo_priv {
   struct rtpp_sessinfo_obj pub;
   struct rtpp_polltbl rtp;
   struct rtpp_polltbl rtcp;
   pthread_mutex_t lock;
};

#define PUB2PVT(pubp) \
  ((struct rtpp_sessinfo_priv *)((char *)(pubp) - offsetof(struct rtpp_sessinfo_priv, pub)))

struct rtpp_sessinfo_obj *
rtpp_sessinfo_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_sessinfo_obj *sessinfo;
    struct rtpp_sessinfo_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_sessinfo_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    sessinfo = &(pvt->pub);
    pvt->rtp.aloclen = cfsp->port_max - cfsp->port_min + 2;
    pvt->rtp.streams_wrt = cfsp->rtp_streams_wrt;
    pvt->rtp.pfds = rtpp_zmalloc(sizeof(struct pollfd) * pvt->rtp.aloclen);
    if (pvt->rtp.pfds == NULL) {
        goto e1;
    }
    pvt->rtp.stuids = rtpp_zmalloc(sizeof(uint64_t) * pvt->rtp.aloclen);
    if (pvt->rtp.stuids == NULL) {
        goto e2;
    }
    pvt->rtcp.aloclen = cfsp->port_max - cfsp->port_min + 2;
    pvt->rtcp.streams_wrt = cfsp->rtcp_streams_wrt;
    pvt->rtcp.pfds = rtpp_zmalloc(sizeof(struct pollfd) * pvt->rtcp.aloclen);
    if (pvt->rtcp.pfds == NULL) {
        goto e3;
    }
    pvt->rtcp.stuids = rtpp_zmalloc(sizeof(uint64_t) * pvt->rtcp.aloclen);
    if (pvt->rtcp.stuids == NULL) {
        goto e4;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e5;
    }

    sessinfo->append = &rtpp_sinfo_append;
    sessinfo->update = &rtpp_sinfo_update;
    sessinfo->remove = &rtpp_sinfo_remove;
    sessinfo->copy_polltbl = &rtpp_sinfo_copy_polltbl;

    return (sessinfo);

e5:
    free(pvt->rtcp.stuids);
e4:
    free(pvt->rtcp.pfds);
e3:
    free(pvt->rtp.stuids);
e2:
    free(pvt->rtp.pfds);
e1:
    free(pvt);
    return (NULL);
}

static void
rtpp_sinfo_append(struct rtpp_sessinfo_obj *sessinfo, struct rtpp_session_obj *sp,
  int index)
{
    int rtp_index, rtcp_index;
    struct rtpp_sessinfo_priv *pvt;

    pvt = PUB2PVT(sessinfo);
    pthread_mutex_lock(&pvt->lock);
    rtp_index = pvt->rtp.curlen;
    rtcp_index = pvt->rtcp.curlen;
    pvt->rtp.pfds[rtp_index].fd = CALL_METHOD(sp->rtp->stream[index]->fd, getfd);
    pvt->rtp.pfds[rtp_index].events = POLLIN;
    pvt->rtp.pfds[rtp_index].revents = 0;
    pvt->rtp.stuids[rtp_index] = sp->rtp->stream[index]->stuid;
    pvt->rtcp.pfds[rtcp_index].fd = CALL_METHOD(sp->rtcp->stream[index]->fd, getfd);
    pvt->rtcp.pfds[rtcp_index].events = POLLIN;
    pvt->rtcp.pfds[rtcp_index].revents = 0;
    pvt->rtcp.stuids[rtcp_index] = sp->rtcp->stream[index]->stuid;
    pvt->rtp.curlen++;
    pvt->rtcp.curlen++;
    pvt->rtp.revision++;
    pvt->rtcp.revision++;
    pthread_mutex_unlock(&pvt->lock);
}

static int
find_polltbl_idx(struct rtpp_polltbl *ptp, uint64_t stuid)
{
    int i;

    for (i = 0; i < ptp->curlen; i++) {
        if (ptp->stuids[i] != stuid)
            continue;
        return (i);
    }
    return (-1);
}

static void
rtpp_sinfo_update(struct rtpp_sessinfo_obj *sessinfo, struct rtpp_session_obj *sp,
  int index, struct rtpp_socket **new_fds)
{
    struct rtpp_sessinfo_priv *pvt;
    int rtp_index, rtcp_index;

    pvt = PUB2PVT(sessinfo);

    pthread_mutex_lock(&pvt->lock);
    rtp_index = find_polltbl_idx(&pvt->rtp, sp->rtp->stream[index]->stuid);
    if (sp->rtp->stream[index]->fd != NULL) {
        assert(rtp_index > -1);
        CALL_METHOD(sp->rtp->stream[index]->fd->rcnt, decref);
    } else {
        assert(rtp_index == -1);
        rtp_index = pvt->rtp.curlen;
        pvt->rtp.curlen++;
        pvt->rtp.stuids[rtp_index] = sp->rtp->stream[index]->stuid;
    }
    sp->rtp->stream[index]->fd = new_fds[0];
    pvt->rtp.pfds[rtp_index].fd = CALL_METHOD(new_fds[0], getfd);
    pvt->rtp.pfds[rtp_index].events = POLLIN;
    pvt->rtp.pfds[rtp_index].revents = 0;
    rtcp_index = find_polltbl_idx(&pvt->rtcp, sp->rtcp->stream[index]->stuid);
    if (sp->rtcp->stream[index]->fd != NULL) {
        assert(rtcp_index > -1);
        CALL_METHOD(sp->rtcp->stream[index]->fd->rcnt, decref);
    } else {
        assert(rtcp_index == -1);
        rtcp_index = pvt->rtcp.curlen;
        pvt->rtcp.curlen++;
        pvt->rtcp.stuids[rtcp_index] = sp->rtcp->stream[index]->stuid;
    }
    sp->rtcp->stream[index]->fd = new_fds[1];
    pvt->rtcp.pfds[rtcp_index].fd = CALL_METHOD(new_fds[1], getfd);
    pvt->rtcp.pfds[rtcp_index].events = POLLIN;
    pvt->rtcp.pfds[rtcp_index].revents = 0;
    pvt->rtp.revision++;
    pvt->rtcp.revision++;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_sinfo_remove(struct rtpp_sessinfo_obj *sessinfo, struct rtpp_session_obj *sp,
  int index)
{
    struct rtpp_sessinfo_priv *pvt;
    int rtp_index, rtcp_index, movelen;

    pvt = PUB2PVT(sessinfo);

    pthread_mutex_lock(&pvt->lock);
    if (sp->rtp->stream[index]->fd != NULL) {
        rtp_index = find_polltbl_idx(&pvt->rtp, sp->rtp->stream[index]->stuid);
        assert(rtp_index > -1);
        assert(pvt->rtp.pfds[rtp_index].fd == CALL_METHOD(sp->rtp->stream[index]->fd, getfd));
        movelen = (pvt->rtp.curlen - rtp_index - 1);
        if (movelen > 0) {
            memmove(&pvt->rtp.pfds[rtp_index], &pvt->rtp.pfds[rtp_index + 1],
              movelen * sizeof(pvt->rtp.pfds[0]));
            memmove(&pvt->rtp.stuids[rtp_index], &pvt->rtp.stuids[rtp_index + 1],
              movelen * sizeof(pvt->rtp.stuids[0]));
        }
        pvt->rtp.curlen--;
        pvt->rtp.revision++;
    }
    if (sp->rtcp->stream[index]->fd != NULL) {
        rtcp_index = find_polltbl_idx(&pvt->rtcp, sp->rtcp->stream[index]->stuid);
        assert(rtcp_index > -1);
        assert(pvt->rtcp.pfds[rtcp_index].fd == CALL_METHOD(sp->rtcp->stream[index]->fd, getfd));
        movelen = (pvt->rtcp.curlen - rtcp_index - 1);
        if (movelen > 0) {
            memmove(&pvt->rtcp.pfds[rtcp_index], &pvt->rtcp.pfds[rtcp_index + 1],
              movelen * sizeof(pvt->rtcp.pfds[0]));
            memmove(&pvt->rtcp.stuids[rtcp_index], &pvt->rtcp.stuids[rtcp_index + 1],
              movelen * sizeof(pvt->rtcp.stuids[0]));
        }
        pvt->rtcp.curlen--;
        pvt->rtcp.revision++;
    }
    pthread_mutex_unlock(&pvt->lock);
}

static int
rtpp_sinfo_copy_polltbl(struct rtpp_sessinfo_obj *sessinfo,
  struct rtpp_polltbl *ptbl, int session_type)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_polltbl *ptbl_pvt;
    struct pollfd *pfds;
    uint64_t *stuids;

    pvt = PUB2PVT(sessinfo);

    ptbl_pvt = (session_type == SESS_RTP) ? &pvt->rtp : &pvt->rtcp;
    pthread_mutex_lock(&pvt->lock);
    if (ptbl_pvt->revision == ptbl->revision) {
        assert(ptbl->curlen == ptbl_pvt->curlen);
        pthread_mutex_unlock(&pvt->lock);
        return (0);
    }
    if (ptbl_pvt->curlen == 0) {
        goto finish_sync;
    }
    if (ptbl_pvt->curlen > ptbl->aloclen) {
        pfds = realloc(ptbl->pfds, (ptbl_pvt->curlen * sizeof(struct pollfd)));
        stuids = realloc(ptbl->stuids, (ptbl_pvt->curlen * sizeof(uint64_t)));
        if (pfds != NULL)
            ptbl->pfds = pfds;
        if (stuids != NULL)
            ptbl->stuids = stuids;
        if (pfds == NULL || stuids == NULL) {
            pthread_mutex_unlock(&pvt->lock);
            return (-1);
        }
        ptbl->aloclen = ptbl_pvt->curlen;
    }
    memcpy(ptbl->pfds, ptbl_pvt->pfds, (ptbl_pvt->curlen * sizeof(struct pollfd)));
    memcpy(ptbl->stuids, ptbl_pvt->stuids, (ptbl_pvt->curlen * sizeof(uint64_t)));
finish_sync:
    ptbl->streams_wrt = ptbl_pvt->streams_wrt;
    ptbl->curlen = ptbl_pvt->curlen;
    ptbl->revision = ptbl_pvt->revision;
    pthread_mutex_unlock(&pvt->lock);
    return (1);
}
