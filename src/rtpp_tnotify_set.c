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

#if defined(HAVE_CONFIG_H)
#include "config_pp.h"
#endif

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
/* asprintf(3) */
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_network.h"
#include "rtpp_tnotify_set.h"
#include "rtpp_tnotify_tgt.h"
#include "rtpp_mallocs.h"

#define RTPP_TNOTIFY_TARGETS_MAX 64
#define RTPP_TNOTIFY_WILDCARDS_MAX 2

#define CC_SELF_STR	"%%CC_SELF%%"

struct rtpp_tnotify_wildcard {
    char *socket_name;
    int socket_type;
    int port;
};

union rtpp_tnotify_entry {
    struct rtpp_tnotify_target rtt;
    struct rtpp_tnotify_wildcard rtw;
};

struct rtpp_tnotify_set_priv {
    struct rtpp_tnotify_set pub;
    struct rtpp_tnotify_target *tp[RTPP_TNOTIFY_TARGETS_MAX];
    int tp_len;
    struct rtpp_tnotify_wildcard *wp[RTPP_TNOTIFY_WILDCARDS_MAX];
    int wp_len;
};

#define PUB2PVT(pubp)      ((struct rtpp_tnotify_set_priv *)((char *)(pubp) - offsetof(struct rtpp_tnotify_set_priv, pub)))

static void rtpp_tnotify_set_dtor(struct rtpp_tnotify_set *);
static int rtpp_tnotify_set_append(struct rtpp_tnotify_set *, const char *, const char **);
static struct rtpp_tnotify_target *rtpp_tnotify_set_lookup(struct rtpp_tnotify_set *,
  const char *, struct sockaddr *, struct sockaddr *);
static int rtpp_tnotify_set_isenabled(struct rtpp_tnotify_set *);

struct rtpp_tnotify_set *
rtpp_tnotify_set_ctor(void)
{
    struct rtpp_tnotify_set_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_tnotify_set_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->pub.dtor = &rtpp_tnotify_set_dtor;
    pvt->pub.append = &rtpp_tnotify_set_append;
    pvt->pub.lookup = &rtpp_tnotify_set_lookup;
    pvt->pub.isenabled = &rtpp_tnotify_set_isenabled;

    return (&pvt->pub);
}

static void
rtpp_tnotify_set_dtor(struct rtpp_tnotify_set *pub)
{
    struct rtpp_tnotify_set_priv *pvt;
    struct rtpp_tnotify_target *tp;
    int i;

    pvt = PUB2PVT(pub);
    for (i = 0; i < pvt->tp_len; i++) {
        tp = pvt->tp[i];
        if (tp->socket_name != NULL)
            free(tp->socket_name);
        if (tp->connected) {
            assert(tp->fd >= 0);
            close(tp->fd);
        }
        if (tp->local != NULL)
            free(tp->local);
        free(tp);
    }
    for (i = 0; i < pvt->wp_len; i++) {
        free(pvt->wp[i]->socket_name);
        free(pvt->wp[i]);
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

/* Returns 0 for a specific target, 1 for wildcard, -1 for an error */
static int
parse_timeout_sock(const char *sock_name, union rtpp_tnotify_entry *rtep,
  const char **e)
{
    char host[512], port[10];
    char *new_sn, **snp;
    int n, rval;
    const char *sprefix, *usock_name;
    struct sockaddr_un *ifsun;
    struct sockaddr *ifsa;

    snp = &rtep->rtt.socket_name;
    rval = 0;
    sprefix = NULL;
    if (strncmp("unix:", sock_name, 5) == 0) {
        usock_name = sock_name + 5;
        rtep->rtt.socket_type = AF_LOCAL;
    } else if (strncmp("tcp:", sock_name, 4) == 0) {
        if (parse_hostport(sock_name + 4, host, sizeof(host), port, sizeof(port), 0, e) != 0) {
            return (-1);
        }
        rtep->rtt.socket_type = AF_INET;
    } else {
        sprefix = "unix:";
        usock_name = sock_name;
        rtep->rtt.socket_type = AF_LOCAL;
    }
    if (rtep->rtt.socket_type == AF_UNIX) {
        if (strlen(usock_name) == 0) {
            *e = "Timeout notification socket name too short";
            return (-1);
        }
        ifsun = sstosun(&rtep->rtt.remote);
        ifsun->sun_family = AF_LOCAL;
        strncpy(ifsun->sun_path, usock_name, sizeof(ifsun->sun_path) - 1);
#if defined(HAVE_SOCKADDR_SUN_LEN)
        ifsun->sun_len = strlen(ifsun->sun_path);
#endif
        rtep->rtt.remote_len = sizeof(struct sockaddr_un);
    } else if (rtep->rtt.socket_type == AF_INET && strcmp(host, CC_SELF_STR) == 0) {
        rtep->rtw.socket_type = AF_INET;
        rtep->rtw.port = atoi(port);
        snp = &rtep->rtt.socket_name;
        rval = 1;
    } else {
        ifsa = sstosa(&rtep->rtt.remote);
        n = resolve(ifsa, AF_INET, host, port, AI_PASSIVE);
        if (n != 0) {
            *e = gai_strerror(n);
            return (-1);
        }
        rtep->rtt.remote_len = SA_LEN(ifsa);
    }
    if (sprefix == NULL) {
        new_sn = strdup(sock_name);
    } else {
        asprintf(&new_sn, "%s%s", sprefix, usock_name);
    }
    if (new_sn == NULL) {
        *e = strerror(errno);
        return (-1);
    }
    *snp = new_sn;

    return (rval);
}

static int
rtpp_tnotify_set_append(struct rtpp_tnotify_set *pub,
  const char *socket_name, const char **e)
{
    int rval;
    struct rtpp_tnotify_set_priv *pvt;
    struct rtpp_tnotify_target *tntp;
    struct rtpp_tnotify_wildcard *tnwp;
    union rtpp_tnotify_entry rte;

    pvt = PUB2PVT(pub);
    memset(&rte, '\0', sizeof(union rtpp_tnotify_entry));
    rval = parse_timeout_sock(socket_name, &rte, e);
    if (rval < 0) {
        goto e0;
    }
    tntp = NULL;
    tnwp = NULL;
    if (rval == 0) {
        if (pvt->tp_len == RTPP_TNOTIFY_TARGETS_MAX) {
            *e = "Number of notify targets exceeds RTPP_TNOTIFY_TARGETS_MAX";
            goto e0;
        }
        tntp = malloc(sizeof(struct rtpp_tnotify_target));
        if (tntp == NULL) {
             *e = strerror(errno);
             goto e1;
        }
        memcpy(tntp, &rte.rtt, sizeof(struct rtpp_tnotify_target));
        tntp->connected = 0;
        tntp->fd = -1;
        pvt->tp[pvt->tp_len] = tntp;
        pvt->tp_len += 1;
    } else {
        if (pvt->wp_len == RTPP_TNOTIFY_WILDCARDS_MAX) {
            *e = "Number of notify wildcards exceeds RTPP_TNOTIFY_WILDCARDS_MAX";
            goto e0;
        }
        tnwp = malloc(sizeof(struct rtpp_tnotify_wildcard));
        if (tnwp == NULL) {
             *e = strerror(errno);
             goto e1;
        }
        memcpy(tnwp, &rte.rtw, sizeof(struct rtpp_tnotify_wildcard));
        pvt->wp[pvt->wp_len] = tnwp;
        pvt->wp_len += 1;
    }

    return (0);

e1:
    if (tntp != NULL)
        free(tntp);
    if (tnwp != NULL)
        free(tnwp);
e0:
    return (-1);
}

static struct rtpp_tnotify_target *
get_tp4wp(struct rtpp_tnotify_set_priv *pvt, struct rtpp_tnotify_wildcard *wp,
  struct sockaddr *ccaddr, struct sockaddr *laddr)
{
    int i;
    struct rtpp_tnotify_target *tp;
    struct sockaddr_in localhost;

    if (ccaddr == NULL || ccaddr->sa_family != AF_INET) {
        /* Request on the unix/IPv6 domain socket, assume it's 127.0.0.1 */
        memset(&localhost, '\0', sizeof(struct sockaddr_in));
        inet_aton("127.0.0.1", &localhost.sin_addr);
        ccaddr = sstosa(&localhost);
        ccaddr->sa_family = AF_INET;
    }
    for (i = 0; i < pvt->tp_len; i++) {
        /* First check against existing targets */
        tp = pvt->tp[i];
        if (tp->socket_name != NULL) {
            /* Only match "automatic" entries */
            continue;
        }
        if (tp->socket_type != wp->socket_type)
            continue;
        if (!ishostseq(ccaddr, sstosa(&tp->remote)))
            continue;
        if (getport(sstosa(&tp->remote)) != wp->port)
            continue;
        return (tp);
    }
    /* Nothing found, crank up a new entry */
    if (pvt->tp_len == RTPP_TNOTIFY_TARGETS_MAX) {
        return (NULL);
    }
    tp = rtpp_zmalloc(sizeof(struct rtpp_tnotify_target));
    if (tp == NULL) {
        return (NULL);
    }
    if (laddr != NULL && laddr->sa_family == ccaddr->sa_family) {
        tp->local = malloc(SA_LEN(laddr));
        if (tp->local == NULL) {
            free(tp);
            return (NULL);
        }
        memcpy(tp->local, laddr, SA_LEN(laddr));
        setanyport(tp->local);
    }
    tp->remote_len = SA_LEN(ccaddr);
    memcpy(&tp->remote, ccaddr, tp->remote_len);
    setport(sstosa(&tp->remote), wp->port);
    tp->socket_type = wp->socket_type;
    tp->connected = 0;
    tp->fd = -1;
    pvt->tp[pvt->tp_len] = tp;
    pvt->tp_len += 1;
    return (tp);
}

static struct rtpp_tnotify_target *
rtpp_tnotify_set_lookup(struct rtpp_tnotify_set *pub, const char *socket_name,
  struct sockaddr *ccaddr, struct sockaddr *laddr)
{
    struct rtpp_tnotify_set_priv *pvt;
    struct rtpp_tnotify_wildcard *wp;
    int i;
    char *sep;

    pvt = PUB2PVT(pub);
    for (i = 0; i < pvt->tp_len; i++) {
        if (pvt->tp[i]->socket_name == NULL)
            continue;
        if (strcmp(pvt->tp[i]->socket_name, socket_name) != 0)
            continue;
        return (pvt->tp[i]);
    }
    sep = strchr(socket_name, ':');
    if (sep == NULL) {
        /*
         * Backwards-compat code, deal with the socket names that skip "unix:"
         * preffix, which was allowed in the rtpp 1.0-2.0.
         */
        for (i = 0; i < pvt->tp_len; i++) {
            if (pvt->tp[i]->socket_name == NULL)
                continue;
            if (pvt->tp[i]->socket_type != AF_LOCAL ||
              strcmp(pvt->tp[i]->socket_name + 5, socket_name) != 0)
                continue;
            return (pvt->tp[i]);
        }
        return (NULL);
    }
    /* Handle wildcards */
    for (i = 0; i < pvt->wp_len; i++) {
        wp = pvt->wp[i];
        if (strcmp(wp->socket_name, socket_name) != 0)
            continue;
        if (ccaddr != NULL && wp->socket_type != ccaddr->sa_family)
            continue;
        return (get_tp4wp(pvt, wp, ccaddr, laddr));
    }
    for (i = 0; i < pvt->wp_len; i++) {
        wp = pvt->wp[i];
        if (strcmp(wp->socket_name, socket_name) != 0)
            continue;
        return (get_tp4wp(pvt, wp, ccaddr, laddr));
    }
    return (NULL);
}

static int
rtpp_tnotify_set_isenabled(struct rtpp_tnotify_set *pub)
{
    struct rtpp_tnotify_set_priv *pvt;

    pvt = PUB2PVT(pub);
    return (pvt->wp_len > 0 || pvt->tp_len > 0);
}
