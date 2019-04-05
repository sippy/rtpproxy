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

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_sessinfo.h"
#include "rtpp_sessinfo_fin.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_mallocs.h"

enum polltbl_hst_ops {HST_ADD, HST_DEL, HST_UPD};

struct rtpp_polltbl_hst_ent {
   uint64_t stuid;
   enum polltbl_hst_ops op;
   struct rtpp_socket *skt;
};

struct rtpp_polltbl_hst {
   int alen;	/* Number of entries allocated */
   int ulen;	/* Number of entries used */
   int ilen;	/* Minimum number of entries to be allocated when need to extend */
   struct rtpp_polltbl_hst_ent *clog;
   struct rtpp_weakref_obj *streams_wrt;
};

struct rtpp_sessinfo_priv {
   struct rtpp_sessinfo pub;
   pthread_mutex_t lock;
   struct rtpp_polltbl_hst hst_rtp;
   struct rtpp_polltbl_hst hst_rtcp;
};

static int rtpp_sinfo_append(struct rtpp_sessinfo *, struct rtpp_session *,
  int, struct rtpp_socket **);
static void rtpp_sinfo_update(struct rtpp_sessinfo *, struct rtpp_session *,
  int, struct rtpp_socket **);
static void rtpp_sinfo_remove(struct rtpp_sessinfo *, struct rtpp_session *,
  int);
static int rtpp_sinfo_sync_polltbl(struct rtpp_sessinfo *, struct rtpp_polltbl *,
  int);
static void rtpp_sessinfo_dtor(struct rtpp_sessinfo_priv *);

#define PUB2PVT(pubp) \
  ((struct rtpp_sessinfo_priv *)((char *)(pubp) - offsetof(struct rtpp_sessinfo_priv, pub)))

static int
rtpp_polltbl_hst_alloc(struct rtpp_polltbl_hst *hp, int alen)
{

    hp->clog = rtpp_zmalloc(sizeof(struct rtpp_polltbl_hst_ent) * alen);
    if (hp->clog == NULL) {
        return (-1);
    }
    hp->alen = hp->ilen = alen;
    return (0);
}

static void
rtpp_polltbl_hst_dtor(struct rtpp_polltbl_hst *hp)
{
    int i;
    struct rtpp_polltbl_hst_ent *hep;

    for (i = 0; i < hp->ulen; i++) {
        hep = hp->clog + i;
        if (hep->skt != NULL) {
            CALL_SMETHOD(hep->skt->rcnt, decref);
        }
    }
    if (hp->alen > 0) {
        free(hp->clog);
    }
}

static int
rtpp_polltbl_hst_extend(struct rtpp_polltbl_hst *hp)
{
    struct rtpp_polltbl_hst_ent *clog_new;

    clog_new = realloc(hp->clog, sizeof(struct rtpp_polltbl_hst_ent) *
      (hp->alen + hp->ilen));
    if (clog_new == NULL) {
        return (-1);
    }
    hp->alen += hp->ilen;
    hp->clog = clog_new;
    return (0);
}

static void
rtpp_polltbl_hst_record(struct rtpp_polltbl_hst *hp, enum polltbl_hst_ops op,
  uint64_t stuid, struct rtpp_socket *skt)
{
    struct rtpp_polltbl_hst_ent *hpe;

    hpe = hp->clog + hp->ulen;
    hpe->op = op;
    hpe->stuid = stuid;
    hpe->skt = skt;
    hp->ulen += 1;
    if (skt != NULL) {
        CALL_SMETHOD(skt->rcnt, incref);
    }
}

struct rtpp_sessinfo *
rtpp_sessinfo_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_sessinfo *sessinfo;
    struct rtpp_sessinfo_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_sessinfo_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    sessinfo = &(pvt->pub);
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e5;
    }
    if (rtpp_polltbl_hst_alloc(&pvt->hst_rtp, 10) != 0) {
        goto e6;
    }
    if (rtpp_polltbl_hst_alloc(&pvt->hst_rtcp, 10) != 0) {
        goto e7;
    }
    pvt->hst_rtp.streams_wrt = cfsp->rtp_streams_wrt;
    pvt->hst_rtcp.streams_wrt = cfsp->rtcp_streams_wrt;

    sessinfo->append = &rtpp_sinfo_append;
    sessinfo->update = &rtpp_sinfo_update;
    sessinfo->remove = &rtpp_sinfo_remove;
    sessinfo->sync_polltbl = &rtpp_sinfo_sync_polltbl;

    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_sessinfo_dtor,
      pvt);
    return (sessinfo);

e7:
    free(pvt->hst_rtp.clog);
e6:
    pthread_mutex_destroy(&pvt->lock);
e5:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
    return (NULL);
}

static void
rtpp_sessinfo_dtor(struct rtpp_sessinfo_priv *pvt)
{

    rtpp_sessinfo_fin(&(pvt->pub));
    rtpp_polltbl_hst_dtor(&pvt->hst_rtp);
    rtpp_polltbl_hst_dtor(&pvt->hst_rtcp);
    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static int
rtpp_sinfo_append(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index, struct rtpp_socket **new_fds)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;

    pvt = PUB2PVT(sessinfo);
    pthread_mutex_lock(&pvt->lock);
    if (pvt->hst_rtp.ulen == pvt->hst_rtp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
            return (-1);
        }
    }
    if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
            return (-1);
        }
    }
    rtp = sp->rtp->stream[index];
    CALL_SMETHOD(rtp, set_skt, new_fds[0]);
    rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_ADD, rtp->stuid, new_fds[0]);
    rtcp = sp->rtcp->stream[index];
    CALL_SMETHOD(rtcp, set_skt, new_fds[1]);
    rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_ADD, rtcp->stuid, new_fds[1]);

    pthread_mutex_unlock(&pvt->lock);
    return (0);
}

static int
find_polltbl_idx(struct rtpp_polltbl *ptp, uint64_t stuid)
{
    int i;

    for (i = 0; i < ptp->curlen; i++) {
        if (ptp->mds[i].stuid != stuid)
            continue;
        return (i);
    }
    return (-1);
}

static void
rtpp_sinfo_update(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index, struct rtpp_socket **new_fds)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;
    struct rtpp_socket *old_fd;

    pvt = PUB2PVT(sessinfo);

    pthread_mutex_lock(&pvt->lock);
    if (pvt->hst_rtp.ulen == pvt->hst_rtp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
            return;
        }
    }
    if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
            return;
        }
    }
    rtp = sp->rtp->stream[index];
    old_fd = CALL_SMETHOD(rtp, update_skt, new_fds[0]);
    if (old_fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_UPD, rtp->stuid, new_fds[0]);
        CALL_SMETHOD(old_fd->rcnt, decref);
    } else {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_ADD, rtp->stuid, new_fds[0]);
    }
    rtcp = sp->rtcp->stream[index];
    old_fd = CALL_SMETHOD(rtcp, update_skt, new_fds[1]);
    if (old_fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_UPD, rtcp->stuid, new_fds[1]);
        CALL_SMETHOD(old_fd->rcnt, decref);
    } else {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_ADD, rtcp->stuid, new_fds[1]);
    }

    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_sinfo_remove(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;
    struct rtpp_socket *fd;

    pvt = PUB2PVT(sessinfo);

    pthread_mutex_lock(&pvt->lock);
    if (pvt->hst_rtp.ulen == pvt->hst_rtp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
            return;
        }
    }
    if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
            return;
        }
    }
    rtp = sp->rtp->stream[index];
    fd = CALL_SMETHOD(rtp, get_skt);
    if (fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_DEL, rtp->stuid, NULL);
        CALL_SMETHOD(fd->rcnt, decref);
    }
    rtcp = sp->rtcp->stream[index];
    fd = CALL_SMETHOD(rtcp, get_skt);
    if (fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_DEL, rtcp->stuid, NULL);
        CALL_SMETHOD(fd->rcnt, decref);
    }

    pthread_mutex_unlock(&pvt->lock);
}

void
rtpp_polltbl_free(struct rtpp_polltbl *ptbl)
{
    int i;

    if (ptbl->aloclen == 0) {
        return;
    }
    if (ptbl->curlen > 0) {
        for (i = 0; i < ptbl->curlen; i++) {
            CALL_SMETHOD(ptbl->mds[i].skt->rcnt, decref);
        }
    }
    free(ptbl->pfds);
    free(ptbl->mds);
}

static int
rtpp_sinfo_sync_polltbl(struct rtpp_sessinfo *sessinfo,
  struct rtpp_polltbl *ptbl, int pipe_type)
{
    struct rtpp_sessinfo_priv *pvt;
    struct pollfd *pfds;
    struct rtpp_polltbl_mdata *mds;
    struct rtpp_polltbl_hst *hp;
    int i;

    pvt = PUB2PVT(sessinfo);

    pthread_mutex_lock(&pvt->lock);
    hp = (pipe_type == PIPE_RTP) ? &pvt->hst_rtp : &pvt->hst_rtcp;

    if (hp->ulen == 0) {
        pthread_mutex_unlock(&pvt->lock);
        return (0);
    }

    if (hp->ulen > ptbl->aloclen - ptbl->curlen) {
        int alen = hp->ulen + ptbl->curlen;

        pfds = realloc(ptbl->pfds, (alen * sizeof(struct pollfd)));
        mds = realloc(ptbl->mds, (alen * sizeof(struct rtpp_polltbl_mdata)));
        if (pfds != NULL)
            ptbl->pfds = pfds;
        if (mds != NULL)
            ptbl->mds = mds;
        if (pfds == NULL || mds == NULL) {
            pthread_mutex_unlock(&pvt->lock);
            return (-1);
        }
        ptbl->aloclen = alen;
    }

    for (i = 0; i < hp->ulen; i++) {
        struct rtpp_polltbl_hst_ent *hep;
        int session_index, movelen;

        hep = hp->clog + i;
        switch (hep->op) {
        case HST_ADD:
#ifdef RTPP_DEBUG
            assert(find_polltbl_idx(ptbl, hep->stuid) < 0);
#endif
            session_index = ptbl->curlen;
            ptbl->pfds[session_index].fd = CALL_METHOD(hep->skt, getfd);
            ptbl->pfds[session_index].events = POLLIN;
            ptbl->pfds[session_index].revents = 0;
            ptbl->mds[session_index].stuid = hep->stuid;
            ptbl->mds[session_index].skt = hep->skt;
            ptbl->curlen++;
            ptbl->revision++;
            break;

        case HST_DEL:
            session_index = find_polltbl_idx(ptbl, hep->stuid);
            assert(session_index > -1);
            CALL_SMETHOD(ptbl->mds[session_index].skt->rcnt, decref);
            movelen = (ptbl->curlen - session_index - 1);
            if (movelen > 0) {
                memmove(&ptbl->pfds[session_index], &ptbl->pfds[session_index + 1],
                  movelen * sizeof(ptbl->pfds[0]));
                memmove(&ptbl->mds[session_index], &ptbl->mds[session_index + 1],
                  movelen * sizeof(ptbl->mds[0]));
            }
            ptbl->curlen--;
            ptbl->revision++;
            break;

        case HST_UPD:
            session_index = find_polltbl_idx(ptbl, hep->stuid);
            assert(session_index > -1);
            CALL_SMETHOD(ptbl->mds[session_index].skt->rcnt, decref);
            ptbl->pfds[session_index].fd = CALL_METHOD(hep->skt, getfd);
            ptbl->pfds[session_index].events = POLLIN;
            ptbl->pfds[session_index].revents = 0;
            ptbl->mds[session_index].skt = hep->skt;
            ptbl->revision++;
            break;
        }
    }
    hp->ulen = 0;

    ptbl->streams_wrt = hp->streams_wrt;
    pthread_mutex_unlock(&pvt->lock);
    return (1);
}
