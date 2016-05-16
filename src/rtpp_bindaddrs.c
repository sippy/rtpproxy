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
#include <stdlib.h>
#include <string.h>

#include "rtpp_defines.h"
#include "rtpp_network.h"

struct bindaddr_list {
    struct sockaddr_storage *bindaddr;
    struct bindaddr_list *next;
};

struct sockaddr *
addr2bindaddr(struct cfg *cf, struct sockaddr *ia, const char **ep)
{
    struct bindaddr_list *bl;

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

struct sockaddr *
host2bindaddr(struct cfg *cf, const char *host, int pf, const char **ep)
{
    int n;
    struct sockaddr_storage ia;
    struct sockaddr *rval;

    /*
     * If user specified * then change it to NULL,
     * that will make getaddrinfo to return addr_any socket
     */
    if (host && (strcmp(host, "*") == 0))
        host = NULL;

    if ((n = resolve(sstosa(&ia), pf, host, SERVICE, AI_PASSIVE)) != 0) {
        *ep = gai_strerror(n);
        return (NULL);
    }
    rval = addr2bindaddr(cf, sstosa(&ia), ep);
    return (rval);
}

struct sockaddr *
bindaddr4af(struct cfg *cf, int af)
{
    struct bindaddr_list *bl;

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
