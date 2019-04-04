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
 * $Id$
 *
 */

#ifndef _SESSION_H_
#define _SESSION_H_

#include <sys/types.h>
#include <sys/socket.h>

#include "rtp.h"

#define MYQ_INIT(headp) {(headp)->first = (headp)->last = NULL;}
#define MYQ_FIRST(headp) ((headp)->first)
#define MYQ_LAST(headp) ((headp)->last)
#define MYQ_NEXT(itemp) ((itemp)->next)
#define MYQ_PREV(itemp) ((itemp)->prev)
#define MYQ_EMPTY(headp) ((headp)->first == NULL)
#define MYQ_FOREACH(itemp, headp) \
  for ((itemp) = (headp)->first; (itemp) != NULL; (itemp) = MYQ_NEXT(itemp))
#define MYQ_FOREACH_REVERSE(itemp, headp) \
  for ((itemp) = (headp)->last; (itemp) != NULL; (itemp) = MYQ_PREV(itemp))
#define MYQ_INSERT_HEAD(headp, new_itemp) { \
    MYQ_PREV(new_itemp) = NULL; \
    MYQ_NEXT(new_itemp) = (headp)->first; \
    if ((headp)->first != NULL) { \
      MYQ_PREV((headp)->first) = (new_itemp); \
    } else { \
      (headp)->last = (new_itemp); \
    } \
    (headp)->first = (new_itemp); \
  }
#define MYQ_INSERT_AFTER(headp, itemp, new_itemp) { \
    MYQ_NEXT(new_itemp) = MYQ_NEXT(itemp); \
    MYQ_PREV(new_itemp) = (itemp); \
    MYQ_NEXT(itemp) = (new_itemp); \
    if (MYQ_NEXT(new_itemp) == NULL) { \
      (headp)->last = (new_itemp); \
    } else { \
      MYQ_PREV(MYQ_NEXT(new_itemp)) = (new_itemp); \
    } \
  }
#define MYQ_REMOVE(headp, itemp) do { \
    if (MYQ_NEXT(itemp) != NULL) \
        MYQ_PREV(MYQ_NEXT(itemp)) = MYQ_PREV(itemp); \
    else { \
        MYQ_LAST(headp) = MYQ_PREV(itemp); \
    } \
    if (MYQ_PREV(itemp) != NULL) \
        MYQ_NEXT(MYQ_PREV(itemp)) = MYQ_NEXT(itemp); \
    else { \
        MYQ_FIRST(headp) = MYQ_NEXT(itemp); \
    } \
} while (0)

struct pkt_hdr_adhoc;
struct rtpp_netaddr;

struct packet {
    struct pkt_hdr_adhoc *pkt;
    struct rtp_info parsed;
    rtp_hdr_t *rpkt;
    struct packet *prev;
    struct packet *next;
};
struct session {
    struct packet *first;
    struct packet *last;
};

enum origin {B_CH, A_CH};

struct channel {
    struct session session;
    void *decoder;
    unsigned int skip;
    enum origin origin;
    struct eaud_crypto *crypto;
    double btime;
    double etime;
};
struct cnode {
    struct channel *cp;
    struct cnode *prev;
    struct cnode *next;
};
struct channels {
    struct cnode *first;
    struct cnode *last;
};
struct stream {
    struct rtpp_netaddr *src;
    struct rtpp_netaddr *dst;
};
struct streams {
    struct stream *first;
    struct stream *last;
};

#define	RPKT(packet)	((rtp_hdr_t *)((packet)->pkt + 1))
#define RPLOAD(packet)	(((unsigned char *)(packet)->rpkt) + (packet)->parsed.data_offset)
#define RPLEN(packet)	((packet)->parsed.data_size)

struct session *session_lookup(struct channels *, uint32_t, struct channel **);
int channel_insert(struct channels *, struct channel *);

#endif
