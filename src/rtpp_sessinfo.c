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

#include "config.h"

#include <sys/stat.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_cfg.h"
#include "rtpp_sessinfo.h"
#include "rtpp_sessinfo_fin.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_mallocs.h"
#include "rtpp_epoll.h"
#include "rtpp_debug.h"

enum polltbl_hst_ops {HST_ADD, HST_DEL, HST_UPD};

struct rtpp_polltbl_hst_ent {
   uint64_t stuid;
   enum polltbl_hst_ops op;
   struct rtpp_socket *skt;
};

struct rtpp_polltbl_hst_part {
   int alen;	/* Number of entries allocated */
   struct rtpp_polltbl_hst_ent *clog;
};

struct rtpp_polltbl_hst {
   int ulen;	/* Number of entries used */
   int ilen;	/* Minimum number of entries to be allocated when need to extend */
   struct rtpp_polltbl_hst_part main;
   struct rtpp_polltbl_hst_part shadow;
   struct rtpp_weakref *streams_wrt;
   pthread_mutex_t lock;
};

struct rtpp_sessinfo_priv {
   struct rtpp_sessinfo pub;
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

DEFINE_SMETHODS(rtpp_sessinfo,
    .append = &rtpp_sinfo_append,
    .update = &rtpp_sinfo_update,
    .remove = &rtpp_sinfo_remove,
    .sync_polltbl = &rtpp_sinfo_sync_polltbl,
);

static int
rtpp_polltbl_hst_alloc(struct rtpp_polltbl_hst *hp, int alen)
{

    hp->main.clog = rtpp_zmalloc(sizeof(struct rtpp_polltbl_hst_ent) * alen);
    if (hp->main.clog == NULL) {
        goto e0;
    }
    hp->shadow.clog = rtpp_zmalloc(sizeof(struct rtpp_polltbl_hst_ent) * alen);
    if (hp->shadow.clog == NULL) {
        goto e1;
    }
    if (pthread_mutex_init(&hp->lock, NULL) != 0)
        goto e2;
    hp->main.alen = hp->shadow.alen = hp->ilen = alen;
    return (0);
e2:
    free(hp->shadow.clog);
e1:
    free(hp->main.clog);
e0:
    return (-1);
}

static void
rtpp_polltbl_hst_dtor(struct rtpp_polltbl_hst *hp)
{
    int i;
    struct rtpp_polltbl_hst_ent *hep;

    for (i = 0; i < hp->ulen; i++) {
        hep = hp->main.clog + i;
        if (hep->skt != NULL) {
            RTPP_OBJ_DECREF(hep->skt);
        }
    }
    if (hp->main.alen > 0) {
        free(hp->shadow.clog);
        free(hp->main.clog);
        pthread_mutex_destroy(&hp->lock);
    }
}

static int
rtpp_polltbl_hst_extend(struct rtpp_polltbl_hst *hp)
{
    struct rtpp_polltbl_hst_ent *clog_new;
    size_t alen = sizeof(struct rtpp_polltbl_hst_ent) *
      (hp->main.alen + hp->ilen);

    clog_new = realloc(hp->main.clog, alen);
    if (clog_new == NULL) {
        return (-1);
    }
    hp->main.clog = clog_new;
    hp->main.alen += hp->ilen;
    return (0);
}

static void
rtpp_polltbl_hst_record(struct rtpp_polltbl_hst *hp, enum polltbl_hst_ops op,
  uint64_t stuid, struct rtpp_socket *skt)
{
    struct rtpp_polltbl_hst_ent *hpe;

    hpe = hp->main.clog + hp->ulen;
    hpe->op = op;
    hpe->stuid = stuid;
    hpe->skt = skt;
    hp->ulen += 1;
    if (skt != NULL) {
        RTPP_OBJ_INCREF(skt);
    }
}

struct rtpp_sessinfo *
rtpp_sessinfo_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_sessinfo *sessinfo;
    struct rtpp_sessinfo_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_sessinfo_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    sessinfo = &(pvt->pub);
    if (rtpp_polltbl_hst_alloc(&pvt->hst_rtp, 10) != 0) {
        goto e6;
    }
    if (rtpp_polltbl_hst_alloc(&pvt->hst_rtcp, 10) != 0) {
        goto e7;
    }
    pvt->hst_rtp.streams_wrt = cfsp->rtp_streams_wrt;
    pvt->hst_rtcp.streams_wrt = cfsp->rtcp_streams_wrt;

    PUBINST_FININIT(&pvt->pub, pvt, rtpp_sessinfo_dtor);
    return (sessinfo);

e7:
    rtpp_polltbl_hst_dtor(&pvt->hst_rtp);
e6:
    RTPP_OBJ_DECREF(&(pvt->pub));
    return (NULL);
}

static void
rtpp_sessinfo_dtor(struct rtpp_sessinfo_priv *pvt)
{

    rtpp_sessinfo_fin(&(pvt->pub));
    rtpp_polltbl_hst_dtor(&pvt->hst_rtp);
    rtpp_polltbl_hst_dtor(&pvt->hst_rtcp);
}

static int
rtpp_sinfo_append(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index, struct rtpp_socket **new_fds)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;

    PUB2PVT(sessinfo, pvt);
    pthread_mutex_lock(&pvt->hst_rtp.lock);
    if (pvt->hst_rtp.ulen == pvt->hst_rtp.main.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
            goto e0;
        }
    }
    pthread_mutex_lock(&pvt->hst_rtcp.lock);
    if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.main.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
            goto e1;
        }
    }
    rtp = sp->rtp->stream[index];
    CALL_SMETHOD(rtp, set_skt, new_fds[0]);
    rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_ADD, rtp->stuid, new_fds[0]);
    pthread_mutex_unlock(&pvt->hst_rtp.lock);

    rtcp = sp->rtcp->stream[index];
    CALL_SMETHOD(rtcp, set_skt, new_fds[1]);
    rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_ADD, rtcp->stuid, new_fds[1]);
    pthread_mutex_unlock(&pvt->hst_rtcp.lock);

    return (0);
e1:
    pthread_mutex_unlock(&pvt->hst_rtcp.lock);
e0:
    pthread_mutex_unlock(&pvt->hst_rtp.lock);
    return (-1);
}

static int
find_polltbl_idx(struct rtpp_polltbl *ptp, uint64_t stuid)
{
    int i, j = -1;

    for (i = 0; i < ptp->curlen; i++) {
        if (ptp->mds[i].stuid != stuid)
            continue;
        RTPP_DBGCODE() {
            assert(j == -1);
            j = i;
        } else {
            return (i);
        }
    }
    return (j);
}

static void
rtpp_sinfo_update(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index, struct rtpp_socket **new_fds)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;
    struct rtpp_socket *old_fd;

    PUB2PVT(sessinfo, pvt);

    pthread_mutex_lock(&pvt->hst_rtp.lock);
    if (pvt->hst_rtp.ulen == pvt->hst_rtp.main.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
            goto e0;
        }
    }
    pthread_mutex_lock(&pvt->hst_rtcp.lock);
    if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.main.alen) {
        if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
            goto e1;
        }
    }
    rtp = sp->rtp->stream[index];
    old_fd = CALL_SMETHOD(rtp, update_skt, new_fds[0]);
    if (old_fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_UPD, rtp->stuid, new_fds[0]);
        pthread_mutex_unlock(&pvt->hst_rtp.lock);
        RTPP_OBJ_DECREF(old_fd);
    } else {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_ADD, rtp->stuid, new_fds[0]);
        pthread_mutex_unlock(&pvt->hst_rtp.lock);
    }
    rtcp = sp->rtcp->stream[index];
    old_fd = CALL_SMETHOD(rtcp, update_skt, new_fds[1]);
    if (old_fd != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_UPD, rtcp->stuid, new_fds[1]);
        pthread_mutex_unlock(&pvt->hst_rtcp.lock);
        RTPP_OBJ_DECREF(old_fd);
    } else {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_ADD, rtcp->stuid, new_fds[1]);
        pthread_mutex_unlock(&pvt->hst_rtcp.lock);
    }
    return;
e1:
    pthread_mutex_unlock(&pvt->hst_rtcp.lock);
e0:
    pthread_mutex_unlock(&pvt->hst_rtp.lock);
}

static void
rtpp_sinfo_remove(struct rtpp_sessinfo *sessinfo, struct rtpp_session *sp,
  int index)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_stream *rtp, *rtcp;
    struct rtpp_socket *fd_rtp, *fd_rtcp;;

    PUB2PVT(sessinfo, pvt);

    rtp = sp->rtp->stream[index];
    rtcp = sp->rtcp->stream[index];
    fd_rtp = CALL_SMETHOD(rtp, get_skt, HEREVAL);
    fd_rtcp = CALL_SMETHOD(rtcp, get_skt, HEREVAL);
    if (fd_rtp != NULL) {
        pthread_mutex_lock(&pvt->hst_rtp.lock);
        if (pvt->hst_rtp.ulen == pvt->hst_rtp.main.alen) {
            if (rtpp_polltbl_hst_extend(&pvt->hst_rtp) < 0) {
                goto e0;
            }
        }
    }
    if (fd_rtcp != NULL) {
        pthread_mutex_lock(&pvt->hst_rtcp.lock);
        if (pvt->hst_rtcp.ulen == pvt->hst_rtcp.main.alen) {
            if (rtpp_polltbl_hst_extend(&pvt->hst_rtcp) < 0) {
                goto e1;
            }
        }
    }
    if (fd_rtp != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtp, HST_DEL, rtp->stuid, NULL);
        pthread_mutex_unlock(&pvt->hst_rtp.lock);
    }
    if (fd_rtcp != NULL) {
        rtpp_polltbl_hst_record(&pvt->hst_rtcp, HST_DEL, rtcp->stuid, NULL);
        pthread_mutex_unlock(&pvt->hst_rtcp.lock);
    }
    if (fd_rtp != NULL)
        RTPP_OBJ_DECREF(fd_rtp);
    if (fd_rtcp != NULL)
        RTPP_OBJ_DECREF(fd_rtcp);
    return;
e1:
    pthread_mutex_unlock(&pvt->hst_rtcp.lock);
e0:
    if (fd_rtp != NULL)
        pthread_mutex_unlock(&pvt->hst_rtp.lock);
}

void
rtpp_polltbl_free(struct rtpp_polltbl *ptbl)
{
    int i;

    if (ptbl->aloclen != 0) {
        for (i = 0; i < ptbl->curlen; i++) {
            int fd = CALL_SMETHOD(ptbl->mds[i].skt, getfd);
            rtpp_epoll_ctl(ptbl->epfd, EPOLL_CTL_DEL, fd, NULL);
            RTPP_OBJ_DECREF(ptbl->mds[i].skt);
        }
        free(ptbl->mds);
    }
    close(ptbl->wakefd[0]);
    close(ptbl->epfd);
}

static int
rtpp_sinfo_sync_polltbl(struct rtpp_sessinfo *sessinfo,
  struct rtpp_polltbl *ptbl, int pipe_type)
{
    struct rtpp_sessinfo_priv *pvt;
    struct rtpp_polltbl_mdata *mds;
    struct rtpp_polltbl_hst *hp;
    struct rtpp_polltbl_hst_ent *clog;
    int i, ulen;

    PUB2PVT(sessinfo, pvt);

    hp = (pipe_type == PIPE_RTP) ? &pvt->hst_rtp : &pvt->hst_rtcp;

    pthread_mutex_lock(&hp->lock);
    if (hp->ulen == 0) {
        pthread_mutex_unlock(&hp->lock);
        return (0);
    }

    if (hp->ulen > ptbl->aloclen - ptbl->curlen) {
        int alen = hp->ulen + ptbl->curlen;

        mds = realloc(ptbl->mds, (alen * sizeof(struct rtpp_polltbl_mdata)));
        if (mds == NULL) {
            goto e0;
        }
        ptbl->mds = mds;
        ptbl->aloclen = alen;
    }

    struct rtpp_polltbl_hst_part hpp = hp->main;
    hp->main = hp->shadow;
    hp->shadow = hpp;
    clog = hpp.clog;
    ulen = hp->ulen;
    hp->ulen = 0;
    ptbl->streams_wrt = hp->streams_wrt;
    pthread_mutex_unlock(&hp->lock);

    for (i = 0; i < ulen; i++) {
        struct rtpp_polltbl_hst_ent *hep;
        int session_index, movelen;
        struct epoll_event event;

        hep = clog + i;
        switch (hep->op) {
        case HST_ADD:
#ifdef RTPP_DEBUG
            assert(find_polltbl_idx(ptbl, hep->stuid) < 0);
#endif
            session_index = ptbl->curlen;
            event.events = EPOLLIN;
            event.data.ptr = hep->skt;
            rtpp_epoll_ctl(ptbl->epfd, EPOLL_CTL_ADD, CALL_SMETHOD(hep->skt, getfd), &event);
            ptbl->mds[session_index].stuid = hep->stuid;
            ptbl->mds[session_index].skt = hep->skt;
            ptbl->curlen++;
            break;

        case HST_DEL:
            session_index = find_polltbl_idx(ptbl, hep->stuid);
            assert(session_index > -1);
            rtpp_epoll_ctl(ptbl->epfd, EPOLL_CTL_DEL, CALL_SMETHOD(ptbl->mds[session_index].skt, getfd), NULL);
            RTPP_OBJ_DECREF(ptbl->mds[session_index].skt);
            movelen = (ptbl->curlen - session_index - 1);
            if (movelen > 0) {
                memmove(&ptbl->mds[session_index], &ptbl->mds[session_index + 1],
                  movelen * sizeof(ptbl->mds[0]));
            }
            ptbl->curlen--;
            break;

        case HST_UPD:
            session_index = find_polltbl_idx(ptbl, hep->stuid);
            assert(session_index > -1);
            rtpp_epoll_ctl(ptbl->epfd, EPOLL_CTL_DEL, CALL_SMETHOD(ptbl->mds[session_index].skt, getfd), NULL);
            RTPP_OBJ_DECREF(ptbl->mds[session_index].skt);
            event.events = EPOLLIN;
            event.data.ptr = hep->skt;
            rtpp_epoll_ctl(ptbl->epfd, EPOLL_CTL_ADD, CALL_SMETHOD(hep->skt, getfd), &event);
            ptbl->mds[session_index].skt = hep->skt;
            break;
        }
    }
    ptbl->revision += ulen;

    return (1);
e0:
    for (i = 0; i < hp->ulen; i++) {
        struct rtpp_polltbl_hst_ent *hep;

        hep = hp->main.clog + i;
        if (hep->skt != NULL) {
            RTPP_OBJ_DECREF(hep->skt);
        }
    }
    hp->ulen = 0;
    pthread_mutex_unlock(&hp->lock);
    return (-1);
}
