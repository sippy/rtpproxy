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

#if defined(HAVE_CONFIG_H)
#include "config_pp.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(NO_ERR_H)
#include <err.h>
#else
#include "rtpp_util.h"
#endif

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_queue.h"
#include "rtpp_session.h"
#include "rtpp_wi.h"

struct rtpp_timeout_handler {
    char *socket_name;
    int socket_type;
    int fd;
    int connected;
    union {
        struct sockaddr_un u;
        struct sockaddr_storage i;
    } remote;
    socklen_t remote_len;
};

struct rtpp_notify_wi
{
    int len;
    struct rtpp_timeout_handler *th;
    rtpp_log_t glog;
    char notify_buf[0];
};

struct rtpp_notify_priv {
    struct rtpp_notify_obj pub;
    struct rtpp_queue *nqueue;
    struct rtpp_wi *sigterm;
    pthread_t thread_id;
    rtpp_log_t glog;
};

#define PUB2PVT(pubp)      ((struct rtpp_notify_priv *)((char *)(pubp) - offsetof(struct rtpp_notify_priv, pub)))

static int rtpp_notify_schedule(struct rtpp_notify_obj *, struct rtpp_session *);
static void rtpp_notify_dtor(struct rtpp_notify_obj *);
static void do_timeout_notification(struct rtpp_notify_wi *, int);

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
            rtpp_wi_free(wi);
            break;
        }
        wi_data = rtpp_wi_data_get_ptr(wi, sizeof(struct rtpp_notify_wi), 0);

        /* main work here */
        do_timeout_notification(wi_data, 1);

        /* deallocate wi */
        rtpp_wi_free(wi);
    }
}

int
parse_hostport(const char *hostport, char *host, int hsize, char *port, int psize, int testonly)
{
    const char *cp;
    int myport;

    cp = strrchr(hostport, ':');
    if (cp == NULL || cp[1] == '\0' || cp == hostport) {
        /* warnx("invalid tcp/udp address");*/
        return -1;
    }
    myport = atoi(cp + 1);
    if (myport <= 0 || myport > 65535) {
        /*warnx("%s: invalid port", cp + 1);*/
        return -1;
    }

    if (testonly != 0)
        return 0;

    if (cp - hostport + 1 > hsize || psize < 6) {
        /*warnx("supplied buffers are too small");*/
        return -1;
    }

    memcpy(host, hostport, cp - hostport);
    host[cp - hostport] = '\0';
    snprintf(port, psize, "%d", myport);
    return 0;
}

#define _ELOGORWARN(ltype, glog, msg, args...) \
    if (glog != NULL) { \
        rtpp_log_ewrite(ltype, glog, msg, ## args); \
    } else { \
        warn(msg, ## args); \
    }

#define _LOGORWARNX(ltype, glog, msg, args...) \
    if (glog != NULL) { \
        rtpp_log_write(ltype, glog, msg, ## args); \
    } else { \
        warnx(msg, ## args); \
    }

static int
parse_timeout_sock(rtpp_log_t glog, const char *sock_name, struct rtpp_timeout_handler *th)
{
    char host[512], port[10];
    char *new_sn;
    int n;

    if (strncmp("unix:", sock_name, 5) == 0) {
        sock_name += 5;
        th->socket_type = PF_LOCAL;
    } else if (strncmp("tcp:", sock_name, 4) == 0) {
        sock_name += 4;
        if (parse_hostport(sock_name, host, sizeof(host), port, sizeof(port), 0) != 0) {
            _LOGORWARNX(RTPP_LOG_ERR, glog, "can't parse host:port in TCP address");
            return (-1);
        }
        th->socket_type = PF_INET;
    } else {
        th->socket_type = PF_LOCAL;
    }
    if (th->socket_type == PF_UNIX) {
        th->remote.u.sun_family = AF_LOCAL;
        strncpy(th->remote.u.sun_path, sock_name, sizeof(th->remote.u.sun_path) - 1);
#if defined(HAVE_SOCKADDR_SUN_LEN)
        th->remote.u.sun_len = strlen(th->remote.u.sun_path);
#endif
        th->remote_len = sizeof(th->remote.u);
    } else {
        n = resolve(sstosa(&(th->remote.i)), AF_INET, host, port, AI_PASSIVE);
        if (n != 0) {
            _LOGORWARNX(RTPP_LOG_ERR, glog, "parse_timeout_sock: getaddrinfo('%s:%s'): %s",
              host, port, gai_strerror(n));
            return (-1);
        }
        th->remote_len = SA_LEN(sstosa(&(th->remote.i)));
    }
    if (strlen(sock_name) == 0) {
        _LOGORWARNX(RTPP_LOG_ERR, glog, "timeout notification socket name too short");
        return (-1);
    }
    new_sn = strdup(sock_name);
    if (new_sn == NULL) {
        _ELOGORWARN(RTPP_LOG_ERR, glog, "can't allocate memory");
        return (-1);
    }
    th->socket_name = new_sn;

    return (0);
}

struct rtpp_notify_obj *
rtpp_notify_ctor(rtpp_log_t glog)
{
    struct rtpp_notify_priv *pvt;

    pvt = malloc(sizeof(struct rtpp_notify_priv));
    if (pvt == NULL) {
        goto e0;
    }
    memset(pvt, '\0', sizeof(struct rtpp_notify_priv));
    pvt->nqueue = rtpp_queue_init(1, "rtpp_notify");
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

    pvt->glog = glog;
    pvt->pub.schedule = &rtpp_notify_schedule;
    pvt->pub.dtor = &rtpp_notify_dtor;

    return (&pvt->pub);

e3:
    rtpp_wi_free(pvt->sigterm);
e2:
    rtpp_queue_destroy(pvt->nqueue);
e1:
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_notify_dtor(struct rtpp_notify_obj *pub)
{
    struct rtpp_notify_priv *pvt;

    pvt = PUB2PVT(pub);

    rtpp_queue_put_item(pvt->sigterm, pvt->nqueue);
    pthread_join(pvt->thread_id, NULL);
    rtpp_queue_destroy(pvt->nqueue);
    free(pvt);
}

static int
rtpp_notify_schedule(struct rtpp_notify_obj *pub, struct rtpp_session *sp)
{
    struct rtpp_notify_wi *wi_data;
    struct rtpp_wi *wi;
    struct rtpp_timeout_handler *th = sp->timeout_data.handler;
    int len;
    struct rtpp_notify_priv *pvt;

    if (th == NULL) {
        /* Not an error, just nothing to do */
        return (0);
    }

    pvt = PUB2PVT(pub);

    if (sp->timeout_data.notify_tag == NULL) {
        /* two 5-digit numbers, space, \0 and \n */
        len = 5 + 5 + 3;
    } else {
        /* string, \0 and \n */
        len = strlen(sp->timeout_data.notify_tag) + 2;
    }

    wi = rtpp_wi_malloc_udata((void **)&wi_data,
      sizeof(struct rtpp_notify_wi) + len);
    if (wi == NULL) {
        return (-1);
    }
    memset(wi_data, '\0', sizeof(struct rtpp_notify_wi) + len);

    wi_data->th = th;
    wi_data->len = len;

    if (sp->timeout_data.notify_tag == NULL) {
        len = snprintf(wi_data->notify_buf, len, "%d %d\n",
          sp->ports[0], sp->ports[1]);
    } else {
        len = snprintf(wi_data->notify_buf, len, "%s\n",
          sp->timeout_data.notify_tag);
    }

    wi_data->glog = pvt->glog;

    rtpp_queue_put_item(wi, pvt->nqueue);
    return (0);
}

static void
reconnect_timeout_handler(rtpp_log_t log, struct rtpp_timeout_handler *th)
{

    assert (th->socket_name != NULL && th->connected == 0);

    if (th->fd == -1) {
        rtpp_log_write(RTPP_LOG_DBUG, log, "connecting timeout socket");
    } else {
        rtpp_log_write(RTPP_LOG_DBUG, log, "reconnecting timeout socket");
        close(th->fd);
    }
    th->fd = socket(th->socket_type, SOCK_STREAM, 0);
    if (th->fd == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, log, "can't create timeout socket");
        return;
    }

    if (connect(th->fd, (struct sockaddr *)&(th->remote), th->remote_len) == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, log, "can't connect to timeout socket");
    } else {
        th->connected = 1;
    }
}

static void
do_timeout_notification(struct rtpp_notify_wi *wi, int retries)
{
    int result;

    if (wi->th->connected == 0) {
        reconnect_timeout_handler(wi->glog, wi->th);

        /* If connect fails, no notification will be sent */
        if (wi->th->connected == 0) {
            rtpp_log_write(RTPP_LOG_ERR, wi->glog, "unable to send timeout notification");
            return;
        }
    }

    do {
        result = send(wi->th->fd, wi->notify_buf, wi->len - 1, 0);
    } while (result == -1 && errno == EINTR);

    if (result < 0) {
        wi->th->connected = 0;
        rtpp_log_ewrite(RTPP_LOG_ERR, wi->glog, "failed to send timeout notification");
        if (retries > 0)
            do_timeout_notification(wi, retries - 1);
    }
}

struct rtpp_timeout_handler *
rtpp_th_init(void)
{
    struct rtpp_timeout_handler *th;

    th = malloc(sizeof(struct rtpp_timeout_handler));
    if (th == NULL) {
        return (NULL);
    }
    memset(th, '\0', sizeof(struct rtpp_timeout_handler));
    th->fd = -1;
    th->connected = 0;
    return (th);
}

char *
rtpp_th_set_sn(struct rtpp_timeout_handler *th, const char *socket_name, rtpp_log_t glog)
{
    char *oldsn;

    oldsn = th->socket_name;
    if (parse_timeout_sock(glog, socket_name, th) != 0) {
        return (NULL);
    }
    if (oldsn != NULL) {
        free(oldsn);
    }
    return (th->socket_name);
}

const char *
rtpp_th_get_sn(struct rtpp_timeout_handler *th)
{

    return (th->socket_name);
}
