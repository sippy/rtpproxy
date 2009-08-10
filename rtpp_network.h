/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id: rtpp_network.h,v 1.21 2009/08/10 23:24:05 sobomax Exp $
 *
 */

#ifndef _RTPP_NETWORK_H_
#define _RTPP_NETWORK_H_

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "rtpp_defines.h"

#define	addr2port(sa)	ntohs(satosin(sa)->sin_port)

/* Function prototypes */
int ishostseq(struct sockaddr *, struct sockaddr *);
int ishostnull(struct sockaddr *);
char *addr2char_r(struct sockaddr *, char *buf, int size);
const char *addr2char(struct sockaddr *);
int resolve(struct sockaddr *, int, const char *, const char *, int);
uint16_t rtpp_in_cksum(void *, int);
struct sockaddr *addr2bindaddr(struct cfg *, struct sockaddr *, const char **);
struct sockaddr *host2bindaddr(struct cfg *, const char *, int, const char **);
int local4remote(struct cfg *, struct sockaddr *, struct sockaddr_storage *);
int extractaddr(const char *, char **, char **, int *);

/* Stripped down version of sockaddr_in* for saving space */
struct sockaddr_in4_s {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
};

struct sockaddr_in6_s {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in6_addr sin_addr;
};

union sockaddr_in_s {
    struct sockaddr_in4_s in4;
    struct sockaddr_in6_s in6;
};

/* Some handy/compat macros */
#if !defined(AF_LOCAL)
#define	AF_LOCAL	AF_UNIX
#endif
#if !defined(PF_LOCAL)
#define	PF_LOCAL	PF_UNIX
#endif

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif
#if !defined(SS_LEN)
#define SS_LEN(ss) \
  (((ss)->ss_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

#if !defined(satosin)
#define	satosin(sa)	((struct sockaddr_in *)(sa))
#endif
#if !defined(satosin6)
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))
#endif
#if !defined(sstosa)
#define	sstosa(ss)	((struct sockaddr *)(ss))
#endif
#if !defined(satoss)
#define	satoss(sa)	((struct sockaddr_storage *)(sa))
#endif

#endif
