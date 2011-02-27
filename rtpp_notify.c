/*
 * Copyright (c) 2010 Sippy Software, Inc., http://www.sippysoft.com
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
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_log.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

struct rtpp_notify_wi
{
    char *notify_buf;
    int len;
    struct rtpp_timeout_handler *th;
    rtpp_log_t glog;
    struct rtpp_notify_wi *next;
};

static pthread_t rtpp_notify_queue;
static pthread_cond_t rtpp_notify_queue_cond;
static pthread_mutex_t rtpp_notify_queue_mutex;
static pthread_mutex_t rtpp_notify_wi_free_mutex;

static int rtpp_notify_dropped_items;

static struct rtpp_notify_wi *rtpp_notify_wi_free;
static struct rtpp_notify_wi *rtpp_notify_wi_queue, *rtpp_notify_wi_queue_tail;

static struct rtpp_notify_wi *rtpp_notify_queue_get_free_item(void);
static void rtpp_notify_queue_put_item(struct rtpp_notify_wi *);
static void do_timeout_notification(struct rtpp_notify_wi *, int);

struct rtpp_notify_wi *
rtpp_notify_queue_get_free_item(void)
{
    struct rtpp_notify_wi *wi;

    pthread_mutex_lock(&rtpp_notify_wi_free_mutex);
    if (rtpp_notify_wi_free == NULL) {
        /* no free work items, allocate one now */
        wi = malloc(sizeof(*wi));
        if (wi == NULL)
            rtpp_notify_dropped_items++;
        memset(wi, '\0', sizeof(*wi));

        pthread_mutex_unlock(&rtpp_notify_wi_free_mutex);
        return wi;
    }

    wi = rtpp_notify_wi_free;

    /* move up rtpp_notify_wi_free */
    rtpp_notify_wi_free = rtpp_notify_wi_free->next;
    pthread_mutex_unlock(&rtpp_notify_wi_free_mutex);

    return wi;
}

static void
rtpp_notify_queue_return_free_item(struct rtpp_notify_wi *wi)
{

    pthread_mutex_lock(&rtpp_notify_wi_free_mutex);

    wi->next = rtpp_notify_wi_free;
    rtpp_notify_wi_free = wi;

    pthread_mutex_unlock(&rtpp_notify_wi_free_mutex);
}

static void
rtpp_notify_queue_put_item(struct rtpp_notify_wi *wi)
{

    pthread_mutex_lock(&rtpp_notify_queue_mutex);

    wi->next = NULL;
    if (rtpp_notify_wi_queue == NULL) {
        rtpp_notify_wi_queue = wi;
        rtpp_notify_wi_queue_tail = wi;
    } else {
        rtpp_notify_wi_queue_tail->next = wi;
        rtpp_notify_wi_queue_tail = wi;
    }

    /* notify worker thread */
    pthread_cond_signal(&rtpp_notify_queue_cond);

    pthread_mutex_unlock(&rtpp_notify_queue_mutex);
}

void
rtpp_notify_queue_run(void)
{
    struct rtpp_notify_wi *wi;

    for (;;) {
        pthread_mutex_lock(&rtpp_notify_queue_mutex);
        while (rtpp_notify_wi_queue == NULL) {
            pthread_cond_wait(&rtpp_notify_queue_cond, &rtpp_notify_queue_mutex);
        }
        wi = rtpp_notify_wi_queue;
        rtpp_notify_wi_queue = wi->next;
        pthread_mutex_unlock(&rtpp_notify_queue_mutex);

        /* main work here */
        do_timeout_notification(wi, 1);

        /* put wi into rtpp_notify_wi_free' tail */
        rtpp_notify_queue_return_free_item(wi);
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

static int
parse_timeout_sock(rtpp_log_t glog, const char *sock_name, struct rtpp_timeout_handler *timeout_handler)
{

    if (strncmp("unix:", sock_name, 5) == 0) {
        sock_name += 5;
        timeout_handler->socket_type = PF_LOCAL;
    } else if (strncmp("tcp:", sock_name, 4) == 0) {
        sock_name += 4;
        if (parse_hostport(sock_name, NULL, 0, NULL, 0, 1) != 0) {
            rtpp_log_ewrite(RTPP_LOG_ERR, glog, "can't parse host:port in TCP address");
            return -1;
        }
        timeout_handler->socket_type = PF_INET;
    } else {
        timeout_handler->socket_type = PF_LOCAL;
    }
    if (strlen(sock_name) == 0) {
        rtpp_log_ewrite(RTPP_LOG_ERR, glog, "timeout notification socket name too short");
        return -1;
    }
    timeout_handler->socket_name = strdup(sock_name);
    if (timeout_handler->socket_name == NULL) {
        rtpp_log_ewrite(RTPP_LOG_ERR, glog, "can't allocate memory");
        return -1;
    }

    return 0;
}

struct rtpp_timeout_handler *
rtpp_notify_init(rtpp_log_t glog, const char *socket_name)
{
    struct rtpp_timeout_handler *th;

    rtpp_notify_wi_free = NULL;
    rtpp_notify_wi_queue = NULL;
    rtpp_notify_wi_queue_tail = NULL;

    rtpp_notify_dropped_items = 0;

    th = malloc(sizeof(*th));
    if (th == NULL)
        return NULL;
    memset(th, '\0', sizeof(*th));
    if (parse_timeout_sock(glog, socket_name, th) != 0) {
        free(th);
        return NULL;
    }
    th->fd = -1;
    th->connected = 0;

    pthread_cond_init(&rtpp_notify_queue_cond, NULL);
    pthread_mutex_init(&rtpp_notify_queue_mutex, NULL);
    pthread_mutex_init(&rtpp_notify_wi_free_mutex, NULL);

    if (pthread_create(&rtpp_notify_queue, NULL, (void *(*)(void *))&rtpp_notify_queue_run, NULL) != 0) {
        free(th);
        return NULL;
    }

    return th;
}

int
rtpp_notify_schedule(struct cfg *cf, struct rtpp_session *sp)
{
    struct rtpp_notify_wi *wi;
    struct rtpp_timeout_handler *th = sp->timeout_data.handler;
    int len;
    char *notify_buf;

    if (th == NULL) {
        /* Not an error, just nothing to do */
        return 0;
    }

    wi = rtpp_notify_queue_get_free_item();
    if (wi == NULL)
        return -1;

    wi->th = th;
    if (sp->timeout_data.notify_tag == NULL) {
        /* two 5-digit numbers, space, \0 and \n */
        len = 5 + 5 + 3;
    } else {
        /* string, \0 and \n */
        len = strlen(sp->timeout_data.notify_tag) + 2;
    }
    if (wi->notify_buf == NULL) {
        wi->notify_buf = malloc(len);
        if (wi->notify_buf == NULL) {
            rtpp_notify_queue_return_free_item(wi);
            return -1;
        }
    } else {
        notify_buf = realloc(wi->notify_buf, len);
        if (notify_buf == NULL) {
            rtpp_notify_queue_return_free_item(wi);
            return -1;
        }
        wi->notify_buf = notify_buf;
    }
    wi->len = len;

    if (sp->timeout_data.notify_tag == NULL) {
        len = snprintf(wi->notify_buf, len, "%d %d\n",
          sp->ports[0], sp->ports[1]);
    } else {
        len = snprintf(wi->notify_buf, len, "%s\n",
          sp->timeout_data.notify_tag);
    }

    wi->glog = cf->stable.glog;

    rtpp_notify_queue_put_item(wi);
    return 0;
}

static void
reconnect_timeout_handler(rtpp_log_t log, struct rtpp_timeout_handler *th)
{
    union {
        struct sockaddr_un u;
        struct sockaddr_storage i;
    } remote;
    char host[512], port[10];
    int remote_len, n;

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
    memset(&remote, '\0', sizeof(remote));
    if (th->socket_type == PF_UNIX) {
        remote.u.sun_family = AF_LOCAL;
        strncpy(remote.u.sun_path, th->socket_name, sizeof(remote.u.sun_path) - 1);
#if defined(HAVE_SOCKADDR_SUN_LEN)
        remote.u.sun_len = strlen(remote.u.sun_path);
#endif
        remote_len = sizeof(remote.u);
    } else {
        assert (parse_hostport(th->socket_name, host, sizeof(host), port, sizeof(port), 0) == 0);
        n = resolve(sstosa(&remote.i), AF_INET, host, port, AI_PASSIVE);
        if (n != 0) {
            rtpp_log_write(RTPP_LOG_ERR, log, "reconnect_timeout_handler: getaddrinfo('%s:s'): %s",
              host, port, gai_strerror(n));
            return;
        }
        remote_len = SA_LEN(sstosa(&remote.i));
    }

    if (connect(th->fd, (struct sockaddr *)&remote, remote_len) == -1) {
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
