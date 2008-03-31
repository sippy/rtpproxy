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
 * $Id: rtpp_session.h,v 1.8 2008/03/31 23:36:12 sobomax Exp $
 *
 */

#ifndef _RTPP_SESSION_H_
#define _RTPP_SESSION_H_

#include <sys/types.h>
#include <sys/socket.h>

#include "rtp_server.h"
#include "rtp_resizer.h"
#include "rtpp_log.h"

struct rtpp_session {
    int ttl;
    unsigned long pcount[4];
    char *call_id;
    char *tag;
    rtpp_log_t log;
    struct rtpp_session* rtcp;
    struct rtpp_session* rtp;
    /* Remote source addresses, one for caller and one for callee */
    struct sockaddr *addr[2];
    /* Flag which tells if we are allowed to update address with RTP src IP */
    int canupdate[2];
    /* Local listen addresses/ports */
    struct sockaddr *laddr[2];
    int ports[2];
    /* Descriptors */
    int fds[2];
    /* Session is complete, that is we received both request and reply */
    int complete;
    int asymmetric[2];
    /* Flags: strong create/delete; weak ones */
    int strong;
    int weak[2];
    /* Pointers to rtpp_record's opaque data type */
    void *rrcs[2];
    struct rtp_server *rtps[2];
    /* References to fd-to-session table */
    int sidx[2];
    /* Reference to active RTP generators table */
    int sridx;
    /* Flag that indicates whether or not address supplied by client can't be trusted */
    int untrusted_addr[2];
    struct rtp_resizer resizers[2];
    struct rtpp_session *prev;
    struct rtpp_session *next;
};

void init_hash_table(struct cfg *);
struct rtpp_session *hash_table_findfirst(struct cfg *, char *);
struct rtpp_session *hash_table_findnext(struct rtpp_session *);
void hash_table_append(struct cfg *, struct rtpp_session *);
void append_session(struct cfg *, struct rtpp_session *, int);
void remove_session(struct cfg *, struct rtpp_session *);
int compare_session_tags(char *, char *, unsigned *);

#endif
