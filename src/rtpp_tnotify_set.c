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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_network.h"
#include "rtpp_tnotify_set.h"

#define RTPP_TNOTIFY_TARGETS_MAX 64

#define CC_SELF_STR	"%%CC_SELF%%"

struct rtpp_tnotify_target {
    char *socket_name;
    int socket_type;
    int wildcard;
    union {
        struct sockaddr_un u;
        struct sockaddr_storage i;
        int wildport;
    } remote;
    socklen_t remote_len;
};

struct rtpp_tnotify_set {
    struct rtpp_tnotify_set_obj pub;
    struct rtpp_tnotify_target *tp[RTPP_TNOTIFY_TARGETS_MAX];
    int tp_len;
};

#define PUB2PVT(pubp)      ((struct rtpp_tnotify_set *)((char *)(pubp) - offsetof(struct rtpp_tnotify_set, pub)))

static void rtpp_tnotify_set_dtor(struct rtpp_tnotify_set_obj *);
static int rtpp_tnotify_set_append(struct rtpp_tnotify_set_obj *, const char *, const char **);

struct rtpp_tnotify_set_obj *
rtpp_tnotify_set_ctor(void)
{
    struct rtpp_tnotify_set *pvt;

    pvt = malloc(sizeof(struct rtpp_tnotify_set));
    if (pvt == NULL) {
        return (NULL);
    }
    memset(pvt, '\0', sizeof(struct rtpp_tnotify_set));
    pvt->pub.dtor = &rtpp_tnotify_set_dtor;
    pvt->pub.append = &rtpp_tnotify_set_append;

    return (&pvt->pub);
}

static void
rtpp_tnotify_set_dtor(struct rtpp_tnotify_set_obj *pub)
{
    struct rtpp_tnotify_set *pvt;
    int i;

    pvt = PUB2PVT(pub);
    for (i = 0; i < pvt->tp_len; i++) {
        free(pvt->tp[i]->socket_name);
        free(pvt->tp[i]);
    }
    free(pvt);
}

static int
parse_hostport(const char *hostport, char *host, int hsize, char *port, int psize,
  int testonly, const char **e)
{
    const char *cp;
    int myport;

    cp = strrchr(hostport, ':');
    if (cp == NULL || cp[1] == '\0' || cp == hostport) {
        *e = "Can't parse host:port: invalid address";
        return (-1);
    }
    myport = atoi(cp + 1);
    if (myport <= 0 || myport > 65535) {
        *e = "Can't parse host:port: invalid port";
        return (-1);
    }

    if (testonly != 0)
        return (0);

    if (cp - hostport + 1 > hsize || psize < 6) {
        *e = "Can't parse host:port: supplied buffers are too small";
        return (-1);
    }

    memcpy(host, hostport, cp - hostport);
    host[cp - hostport] = '\0';
    snprintf(port, psize, "%d", myport);
    return (0);
}

static int
parse_timeout_sock(const char *sock_name, struct rtpp_tnotify_target *th,
  const char **e)
{
    char host[512], port[10];
    char *new_sn;
    int n;

    if (strncmp("unix:", sock_name, 5) == 0) {
        sock_name += 5;
        th->socket_type = PF_LOCAL;
    } else if (strncmp("tcp:", sock_name, 4) == 0) {
        sock_name += 4;
        if (parse_hostport(sock_name, host, sizeof(host), port, sizeof(port), 0, e) != 0) {
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
    } else if (strcmp(host, CC_SELF_STR) == 0) {
        th->wildcard = 1;
        th->remote.wildport = atoi(port);
    } else {
        n = resolve(sstosa(&(th->remote.i)), AF_INET, host, port, AI_PASSIVE);
        if (n != 0) {
            *e = gai_strerror(n);
            return (-1);
        }
        th->remote_len = SA_LEN(sstosa(&(th->remote.i)));
    }
    if (strlen(sock_name) == 0) {
        *e = "Timeout notification socket name too short";
        return (-1);
    }
    new_sn = strdup(sock_name);
    if (new_sn == NULL) {
        *e = strerror(errno);
        return (-1);
    }
    th->socket_name = new_sn;

    return (0);
}

static int
rtpp_tnotify_set_append(struct rtpp_tnotify_set_obj *pub,
const char *socket_name, const char **e)
{
    struct rtpp_tnotify_set *pvt;
    struct rtpp_tnotify_target *tntp;

    pvt = PUB2PVT(pub);
    if (pvt->tp_len == RTPP_TNOTIFY_TARGETS_MAX) {
        *e = "Number of notify sockets exceeds RTPP_TNOTIFY_TARGETS_MAX";
        goto e0;
    }
    tntp = malloc(sizeof(struct rtpp_tnotify_target));
    if (tntp == NULL) {
         *e = strerror(errno);
         goto e0;
    }
    memset(tntp, '\0', sizeof(struct rtpp_tnotify_target));
    if (parse_timeout_sock(socket_name, tntp, e) != 0) {
        goto e1;
    }
    pvt->tp[pvt->tp_len] = tntp;
    pvt->tp_len += 1;
    return (0);

e1:
    free(tntp);
e0:
    return (-1);
}
