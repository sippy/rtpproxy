/*
 * Copyright (c) 2010-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#if defined(HAVE_CONFIG_H)
#include "config_pp.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_queue.h"
#include "rtpp_tnotify_tgt.h"
#include "rtpp_mallocs.h"
#include "rtpp_wi.h"
#include "rtpp_wi_data.h"
#include "rtpp_wi_sgnl.h"

struct rtpp_notify_wi
{
    int len;
    struct rtpp_tnotify_target *rttp;
    struct rtpp_log *glog;
    const char *ntype;
    char notify_buf[0];
};

struct rtpp_notify_priv {
    struct rtpp_notify pub;
    struct rtpp_queue *nqueue;
    struct rtpp_wi *sigterm;
    pthread_t thread_id;
    struct rtpp_log *glog;
};

static int rtpp_notify_schedule(struct rtpp_notify *,
  struct rtpp_tnotify_target *, const rtpp_str_t *, const char *);
static void rtpp_notify_dtor(struct rtpp_notify_priv *);
static void do_notification(struct rtpp_notify_wi *, int);

static void
rtpp_notify_queue_run(void *arg)
{
    struct rtpp_wi *wi;
    struct rtpp_notify_wi *wi_data;
    struct rtpp_notify_priv *pvt;

    pvt = (struct rtpp_notify_priv *)arg;
    for (;;) {
        wi = rtpp_queue_get_item(pvt->nqueue, 0);
        if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
            RTPP_OBJ_DECREF(wi);
            break;
        }
        wi_data = rtpp_wi_data_get_ptr(wi, sizeof(struct rtpp_notify_wi), 0);

        /* main work here */
        do_notification(wi_data, 3);

        /* deallocate wi */
        RTPP_OBJ_DECREF(wi_data->glog);
        RTPP_OBJ_DECREF(wi);
    }
}

struct rtpp_notify *
rtpp_notify_ctor(struct rtpp_log *glog)
{
    struct rtpp_notify_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_notify_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->nqueue = rtpp_queue_init(RTPQ_SMALL_CB_LEN, "rtpp_notify");
    if (pvt->nqueue == NULL) {
        goto e1;
    }

    /* Pre-allocate sigterm, so that we don't have any malloc() in dtor() */
    pvt->sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (pvt->sigterm == NULL) {
        goto e2;
    }

    if (pthread_create(&pvt->thread_id, NULL, (void *(*)(void *))&rtpp_notify_queue_run, pvt) != 0) {
        goto e3;
    }
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(pvt->thread_id, "rtpp_notify_queue");
#endif

    RTPP_OBJ_INCREF(glog);
    pvt->glog = glog;
    pvt->pub.schedule = &rtpp_notify_schedule;

    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_notify_dtor,
      pvt);
    return (&pvt->pub);

e3:
    RTPP_OBJ_DECREF(pvt->sigterm);
e2:
    rtpp_queue_destroy(pvt->nqueue);
e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
rtpp_notify_dtor(struct rtpp_notify_priv *pvt)
{

    rtpp_queue_put_item(pvt->sigterm, pvt->nqueue);
    pthread_join(pvt->thread_id, NULL);
    rtpp_queue_destroy(pvt->nqueue);
    RTPP_OBJ_DECREF(pvt->glog);
}

static int
rtpp_notify_schedule(struct rtpp_notify *pub,
  struct rtpp_tnotify_target *rttp, const rtpp_str_t *notify_tag,
  const char *notify_type)
{
    struct rtpp_notify_wi *wi_data;
    struct rtpp_wi *wi;
    int len;
    struct rtpp_notify_priv *pvt;

    PUB2PVT(pub, pvt);

    /* string, \0 and \n */
    len = notify_tag->len + 2;

    wi = rtpp_wi_malloc_udata((void **)&wi_data,
      sizeof(struct rtpp_notify_wi) + len);
    if (wi == NULL) {
        return (-1);
    }
    memset(wi_data, '\0', sizeof(struct rtpp_notify_wi));

    wi_data->rttp = rttp;
    wi_data->len = len;
    RTPP_OBJ_INCREF(pvt->glog);
    wi_data->glog = pvt->glog;
    wi_data->ntype = notify_type;

    memcpy(wi_data->notify_buf, notify_tag->s, notify_tag->len);
    wi_data->notify_buf[notify_tag->len] = '\n';

    rtpp_queue_put_item(wi, pvt->nqueue);
    return (0);
}

static void
reconnect_handler(const struct rtpp_notify_wi *wi)
{

    assert (wi->rttp->connected == 0);
    assert (wi->rttp->socket_type != RTPP_TNS_FD);

    if (wi->rttp->fd == -1) {
        RTPP_LOG(wi->glog, RTPP_LOG_DBUG, "connecting %s socket", wi->ntype);
    } else {
        RTPP_LOG(wi->glog, RTPP_LOG_DBUG, "reconnecting %s socket", wi->ntype);
        close(wi->rttp->fd);
    }
    wi->rttp->fd = socket(RTPP_TNT_STYPE(wi->rttp), SOCK_STREAM, 0);
    if (wi->rttp->fd == -1) {
        RTPP_ELOG(wi->glog, RTPP_LOG_ERR, "can't create %s socket", wi->ntype);
        return;
    }
    if (wi->rttp->local != NULL) {
        if (bind(wi->rttp->fd, wi->rttp->local, SA_LEN(wi->rttp->local)) < 0) {
            RTPP_ELOG(wi->glog, RTPP_LOG_ERR, "can't bind %s socket", wi->ntype);
            goto e0;
        }
    }
    if (connect(wi->rttp->fd, (struct sockaddr *)&(wi->rttp->remote), wi->rttp->remote_len) == -1) {
        RTPP_ELOG(wi->glog, RTPP_LOG_ERR, "can't connect to %s socket", wi->ntype);
        goto e0;
    } else {
        wi->rttp->connected = 1;
    }
    return;

e0:
    close(wi->rttp->fd);
    wi->rttp->fd = -1;
    return;
}

static void
do_notification(struct rtpp_notify_wi *wi, int retries)
{
    int result;

    if (wi->rttp->connected == 0) {
        reconnect_handler(wi);

        /* If connect fails, no notification will be sent */
        if (wi->rttp->connected == 0) {
            RTPP_LOG(wi->glog, RTPP_LOG_ERR, "unable to send %s notification",
              wi->ntype);
            return;
        }
    }

    do {
        result = send(wi->rttp->fd, wi->notify_buf, wi->len - 1, 0);
    } while (result == -1 && errno == EINTR);

    if (result < 0) {
        wi->rttp->connected = 0;
        RTPP_ELOG(wi->glog, RTPP_LOG_ERR, "failed to send %s notification",
          wi->ntype);
        if (retries > 0)
            do_notification(wi, retries - 1);
    }
}
