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

#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

void
init_hash_table(struct cfg_stable *cf)
{
    int i;

    for (i = 0; i < 256; i++) {
	cf->rand_table[i] = random();
    }
}

static uint8_t
hash_string(struct cfg_stable *cf, const char *bp, const char *ep)
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

    hash = hash_string(&cf->stable, sp->call_id, NULL);

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

static void
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
    hash = hash_string(&cf->stable, sp->call_id, NULL);
    /* Make sure we are removing the right session */
    assert(cf->hash_table[hash] == sp);
    cf->hash_table[hash] = sp->next;
    if (sp->next != NULL) {
	sp->next->prev = NULL;
    }
}

struct rtpp_session *
session_findfirst(struct cfg *cf, const char *call_id)
{
    uint8_t hash;
    struct rtpp_session *sp;

    /* Make sure structure is properly locked */
    assert(pthread_mutex_islocked(&cf->glock) == 1);

    hash = hash_string(&cf->stable, call_id, NULL);
    for (sp = cf->hash_table[hash]; sp != NULL; sp = sp->next) {
	if (strcmp(sp->call_id, call_id) == 0) {
	    break;
	}
    }
    return (sp);
}

struct rtpp_session *
session_findnext(struct cfg *cf, struct rtpp_session *psp)
{
    struct rtpp_session *sp;

    /* Make sure structure is properly locked */
    assert(pthread_mutex_islocked(&cf->glock) == 1);

    for (sp = psp->next; sp != NULL; sp = sp->next) {
	if (strcmp(sp->call_id, psp->call_id) == 0) {
	    break;
	}
    }
    return (sp);
}

void
append_session(struct cfg *cf, struct rtpp_session *sp, int index)
{

    /* Make sure structure is properly locked */
    assert(pthread_mutex_islocked(&cf->glock) == 1);

    if (sp->fds[index] != -1) {
        pthread_mutex_lock(&cf->sessinfo.lock);
	cf->sessinfo.sessions[cf->sessinfo.nsessions] = sp;
	cf->sessinfo.pfds[cf->sessinfo.nsessions].fd = sp->fds[index];
	cf->sessinfo.pfds[cf->sessinfo.nsessions].events = POLLIN;
	cf->sessinfo.pfds[cf->sessinfo.nsessions].revents = 0;
	sp->sidx[index] = cf->sessinfo.nsessions;
	cf->sessinfo.nsessions++;
        pthread_mutex_unlock(&cf->sessinfo.lock);
    } else {
	sp->sidx[index] = -1;
    }
}

void
remove_session(struct cfg *cf, struct rtpp_session *sp)
{
    int i;

    /* Make sure structure is properly locked */
    assert(pthread_mutex_islocked(&cf->glock) == 1);
    assert(pthread_mutex_islocked(&cf->sessinfo.lock) == 1);

    rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped", sp->pcount[0], sp->pcount[1],
      sp->pcount[2], sp->pcount[3]);
    rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTCP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped", sp->rtcp->pcount[0],
      sp->rtcp->pcount[1], sp->rtcp->pcount[2], sp->rtcp->pcount[3]);
    rtpp_log_write(RTPP_LOG_INFO, sp->log, "session on ports %d/%d is cleaned up",
      sp->ports[0], sp->ports[1]);
    for (i = 0; i < 2; i++) {
	if (sp->addr[i] != NULL)
	    free(sp->addr[i]);
	if (sp->prev_addr[i] != NULL)
	    free(sp->prev_addr[i]);
	if (sp->rtcp->addr[i] != NULL)
	    free(sp->rtcp->addr[i]);
	if (sp->rtcp->prev_addr[i] != NULL)
	    free(sp->rtcp->prev_addr[i]);
	if (sp->fds[i] != -1) {
	    close(sp->fds[i]);
	    assert(cf->sessinfo.sessions[sp->sidx[i]] == sp);
	    cf->sessinfo.sessions[sp->sidx[i]] = NULL;
	    assert(cf->sessinfo.pfds[sp->sidx[i]].fd == sp->fds[i]);
	    cf->sessinfo.pfds[sp->sidx[i]].fd = -1;
	    cf->sessinfo.pfds[sp->sidx[i]].events = 0;
	}
	if (sp->rtcp->fds[i] != -1) {
	    close(sp->rtcp->fds[i]);
	    assert(cf->sessinfo.sessions[sp->rtcp->sidx[i]] == sp->rtcp);
	    cf->sessinfo.sessions[sp->rtcp->sidx[i]] = NULL;
	    assert(cf->sessinfo.pfds[sp->rtcp->sidx[i]].fd == sp->rtcp->fds[i]);
	    cf->sessinfo.pfds[sp->rtcp->sidx[i]].fd = -1;
	    cf->sessinfo.pfds[sp->rtcp->sidx[i]].events = 0;
	}
	if (sp->rrcs[i] != NULL)
	    rclose(sp, sp->rrcs[i], 1);
	if (sp->rtcp->rrcs[i] != NULL)
	    rclose(sp, sp->rtcp->rrcs[i], 1);
	if (sp->rtps[i] != NULL) {
	    cf->rtp_servers[sp->sridx] = NULL;
	    rtp_server_free(sp->rtps[i]);
	}
	if (sp->codecs[i] != NULL)
	    free(sp->codecs[i]);
	if (sp->rtcp->codecs[i] != NULL)
	    free(sp->rtcp->codecs[i]);
    }
    if (sp->timeout_data.notify_tag != NULL)
	free(sp->timeout_data.notify_tag);
    hash_table_remove(cf, sp);
    if (sp->call_id != NULL)
	free(sp->call_id);
    if (sp->tag != NULL)
	free(sp->tag);
    rtpp_log_close(sp->log);
    free(sp->rtcp);
    rtp_resizer_free(&sp->resizers[0]);
    rtp_resizer_free(&sp->resizers[1]);
    free(sp);
    cf->sessions_active--;
}

int
compare_session_tags(const char *tag1, const char *tag0, unsigned *medianum_p)
{
    size_t len0 = strlen(tag0);

    if (!strncmp(tag1, tag0, len0)) {
	if (tag1[len0] == ';') {
	    if (medianum_p != NULL)
		*medianum_p = strtoul(tag1 + len0 + 1, NULL, 10);
	    return 2;
	}
	if (tag1[len0] == '\0')
	    return 1;
	return 0;
    }
    return 0;
}

int
find_stream(struct cfg *cf, const char *call_id, const char *from_tag,
  const char *to_tag, struct rtpp_session **spp)
{
    const char *cp1, *cp2;

    /* Make sure structure is properly locked */
    assert(pthread_mutex_islocked(&cf->glock) == 1);

    for (*spp = session_findfirst(cf, call_id); *spp != NULL; *spp = session_findnext(cf, *spp)) {
	if (strcmp((*spp)->tag, from_tag) == 0) {
	    return 0;
	} else if (to_tag != NULL) {
	    switch (compare_session_tags((*spp)->tag, to_tag, NULL)) {
	    case 1:
		/* Exact tag match */
		return 1;

	    case 2:
		/*
		 * Reverse tag match without medianum. Medianum is always
		 * applied to the from tag, verify that.
		 */
		cp1 = strrchr((*spp)->tag, ';');
		cp2 = strrchr(from_tag, ';');
		if (cp2 != NULL && strcmp(cp1, cp2) == 0)
		    return 1;
		break;

	    default:
		break;
	    }
	}
    }
    return -1;
}

int
get_ttl(struct rtpp_session *sp)
{

    switch(sp->ttl_mode) {
    case TTL_UNIFIED:
	return (MAX(sp->ttl[0], sp->ttl[1]));

    case TTL_INDEPENDENT:
	return (MIN(sp->ttl[0], sp->ttl[1]));

    default:
	/* Shouldn't happen[tm] */
	break;
    }
    abort();
    return 0;
}
