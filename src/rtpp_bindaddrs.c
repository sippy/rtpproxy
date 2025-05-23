/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_defines.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_network.h"
#include "rtpp_mallocs.h"
#include "rtpp_bindaddrs.h"

struct bindaddr_list {
    struct sockaddr_storage *bindaddr;
    struct bindaddr_list *next;
};

struct rtpp_bindaddrs_pvt {
    struct rtpp_bindaddrs pub;
    struct bindaddr_list *bindaddr_list;
    pthread_mutex_t bindaddr_lock;
};

static const struct sockaddr *
addr2bindaddr(struct rtpp_bindaddrs *pub, const struct sockaddr *ia, const char **ep)
{
    struct bindaddr_list *bl;
    struct rtpp_bindaddrs_pvt *cf;

    PUB2PVT(pub, cf);
    pthread_mutex_lock(&cf->bindaddr_lock);
    for (bl = cf->bindaddr_list; bl != NULL; bl = bl->next) {
        if (ishostseq(sstosa(bl->bindaddr), ia) != 0) {
            pthread_mutex_unlock(&cf->bindaddr_lock);
            return (sstosa(bl->bindaddr));
        }
    }
    bl = malloc(sizeof(*bl) + sizeof(*bl->bindaddr));
    if (bl == NULL) {
        pthread_mutex_unlock(&cf->bindaddr_lock);
        *ep = strerror(errno);
        return (NULL);
    }
    bl->bindaddr = (struct sockaddr_storage *)((char *)bl + sizeof(*bl));
    memcpy(bl->bindaddr, ia, SA_LEN(ia));
    bl->next = cf->bindaddr_list;
    cf->bindaddr_list = bl;
    pthread_mutex_unlock(&cf->bindaddr_lock);
    return (sstosa(bl->bindaddr));
}

static const struct sockaddr *
host2bindaddr(struct rtpp_bindaddrs *pub, const char *host, int pf,
  int ai_flags, const char **ep)
{
    int n;
    struct sockaddr_storage ia;
    const struct sockaddr *rval;

    /*
     * If user specified * then change it to NULL,
     * that will make getaddrinfo to return addr_any socket
     */
    if (host != NULL && is_wildcard(host, pf))
        host = NULL;

    if (host != NULL) {
        ai_flags |= is_numhost(host, pf) ? AI_NUMERICHOST : 0;
    } else {
        ai_flags &= ~AI_ADDRCONFIG;
    }

    if ((n = resolve(sstosa(&ia), pf, host, SERVICE, ai_flags)) != 0) {
        *ep = gai_strerror(n);
        return (NULL);
    }
    rval = addr2bindaddr(pub, sstosa(&ia), ep);
    return (rval);
}

static const struct sockaddr *
bindaddr4af(struct rtpp_bindaddrs *pub, int af)
{
    struct bindaddr_list *bl;
    struct rtpp_bindaddrs_pvt *cf;

    PUB2PVT(pub, cf);
    pthread_mutex_lock(&cf->bindaddr_lock);
    for (bl = cf->bindaddr_list; bl != NULL; bl = bl->next) {
        if (sstosa(bl->bindaddr)->sa_family == af) {
            pthread_mutex_unlock(&cf->bindaddr_lock);
            return (sstosa(bl->bindaddr));
        }
    }
    pthread_mutex_unlock(&cf->bindaddr_lock);
    return (NULL);
}

static void
rtpp_bindaddrs_dtor(struct rtpp_bindaddrs *pub)
{
    struct rtpp_bindaddrs_pvt *cf;
    struct bindaddr_list *bl, *bl_next;

    PUB2PVT(pub, cf);
    for (bl = cf->bindaddr_list; bl != NULL; bl = bl_next) {
        bl_next = bl->next;
        free(bl);
    }
    free(cf);
}

static const struct sockaddr *
rtpp_bindaddrs_local4remote(struct rtpp_bindaddrs *pub, const struct rtpp_cfg *cfsp,
  struct rtpp_log *log, int pf, const char *host, const char *port)
{
    struct sockaddr_storage local_addr;
    const struct sockaddr *rval;
    const char *errmsg;

    int ai_flags = cfsp->no_resolve ? AI_NUMERICHOST : 0;
    int n = resolve(sstosa(&local_addr), pf, host, port, ai_flags);
    if (n != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "invalid remote address: %s: %s", host,
          gai_strerror(n));
        return (NULL);
    }
    if (local4remote(sstosa(&local_addr), &local_addr) == -1) {
        RTPP_LOG(log, RTPP_LOG_ERR, "can't find local address for remote address: %s",
          host);
        return (NULL);
    }
    rval = addr2bindaddr(pub, sstosa(&local_addr), &errmsg);
    if (rval == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "invalid local address: %s", errmsg);
        return (NULL);
    }
    return (rval);
}

struct rtpp_bindaddrs *
rtpp_bindaddrs_ctor(void)
{
    struct rtpp_bindaddrs_pvt *cf;

    cf = rtpp_zmalloc(sizeof(*cf));
    if (cf == NULL)
        goto e0;
    if (pthread_mutex_init(&cf->bindaddr_lock, NULL) != 0)
        goto e1;
    cf->pub.addr2 = addr2bindaddr;
    cf->pub.host2 = host2bindaddr;
    cf->pub.foraf = bindaddr4af;
    cf->pub.dtor = rtpp_bindaddrs_dtor;
    cf->pub.local4remote = rtpp_bindaddrs_local4remote;
    return (&(cf->pub));
e1:
    free(cf);
e0:
    return (NULL);
}
