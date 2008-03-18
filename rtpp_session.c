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

#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_session.h"

void
init_hash_table(struct cfg *cf)
{
    int i;

    for (i = 0; i < 256; i++) {
	cf->rand_table[i] = random();
    }
}

static uint8_t
hash_string(struct cfg *cf, char *bp, char *ep)
{
    uint8_t res;

    for (res = cf->rand_table[0]; bp[0] != '\0' && bp != ep; bp++) {
	res = cf->rand_table[res ^ bp[0]];
    }
    return res;
}

void
hash_table_append(struct cfg *cf, struct rtpp_session *sp)
{
    uint8_t hash;
    struct rtpp_session *tsp;

    assert(sp->rtcp != NULL);

    hash = hash_string(cf, sp->call_id, NULL);

    rtpp_log_write(RTPP_LOG_DBUG, cf->glog, "hash_table_append: hash(%s) = %d", sp->call_id, hash);

    tsp = cf->hash_table[hash];
    if (tsp == NULL) {
	cf->hash_table[hash] = sp;
	sp->prev = sp->next = NULL;
	return;
    }
    while (tsp->next != NULL) {
	tsp = tsp->next;
    }
    tsp->next = sp;
    sp->prev = tsp;
    sp->next = NULL;
}

void
hash_table_remove(struct cfg *cf, struct rtpp_session *sp)
{
    uint8_t hash;

    assert(sp->rtcp != NULL);

    if (sp->prev != NULL) {
	sp->prev->next = sp->next;
	if (sp->next != NULL) {
	    sp->next->prev = sp->prev;
	}
	return;
    }
    hash = hash_string(cf, sp->call_id, NULL);
    /* Make sure we are removing the right session */
    assert(cf->hash_table[hash] == sp);
    cf->hash_table[hash] = sp->next;
    if (sp->next != NULL) {
	sp->next->prev = NULL;
    }
}

struct rtpp_session *
hash_table_findfirst(struct cfg *cf, char *call_id)
{
    uint8_t hash;
    struct rtpp_session *sp;

    hash = hash_string(cf, call_id, NULL);
    for (sp = cf->hash_table[hash]; sp != NULL; sp = sp->next) {
	if (strcmp(sp->call_id, call_id) == 0) {
	    break;
	}
    }
    return (sp);
}

struct rtpp_session *
hash_table_findnext(struct rtpp_session *psp)
{
    struct rtpp_session *sp;

    for (sp = psp->next; sp != NULL; sp = sp->next) {
	if (strcmp(sp->call_id, psp->call_id) == 0) {
	    break;
	}
    }
    return (sp);
}
