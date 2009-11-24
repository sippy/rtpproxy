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
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

#define SESSION_QUEUE_ENTRIES 50

static struct session_queue_item session_queue_items[SESSION_QUEUE_ENTRIES];
static pthread_mutex_t session_queue_item_pool_lock;
static pthread_cond_t session_queue_item_pool_cv;
static struct session_queue_item *session_queue_item_pool;

static pthread_mutex_t session_queue_lock;
static struct session_queue_item *append_buffer = NULL;
static struct session_queue_item *append_buffer_last_item = NULL;
static struct session_queue_item *session_remove_queue = NULL;
static struct session_queue_item *session_append_queue = NULL;

static struct rtpp_session *free_sessions_queue = NULL;
struct rtpp_session *all_sessions = NULL;

static pthread_mutex_t ref_count_lock;
static pthread_mutex_t free_queue_lock;
static pthread_mutex_t session_cleaner_lock;
static pthread_cond_t session_cleaner_cv;

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

    if (sp->removed_from_hash)
        return;
    sp->removed_from_hash = 1;

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
session_findfirst(struct cfg *cf, char *call_id)
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
session_findnext(struct rtpp_session *psp)
{
    struct rtpp_session *sp;

    for (sp = psp->next; sp != NULL; sp = sp->next) {
	if (strcmp(sp->call_id, psp->call_id) == 0) {
	    break;
	}
    }
    return (sp);
}

void 
session_storage_init()
{
    int i;
    struct session_queue_item *prev;

    pthread_mutex_init(&session_queue_item_pool_lock, NULL);
    pthread_cond_init(&session_queue_item_pool_cv, NULL);
    prev = session_queue_item_pool = &session_queue_items[0];
    for (i = 1; i < SESSION_QUEUE_ENTRIES; ++i) {
        prev->next = &session_queue_items[i];
        prev = prev->next;
    }
    session_queue_items[SESSION_QUEUE_ENTRIES - 1].next = NULL;

    pthread_mutex_init(&session_queue_lock, NULL);
    pthread_mutex_init(&ref_count_lock, NULL);
    pthread_mutex_init(&free_queue_lock, NULL);
    pthread_mutex_init(&session_cleaner_lock, NULL);
    pthread_cond_init(&session_cleaner_cv, NULL);
}

void
dec_ref_count(struct rtpp_session *sp)
{
    pthread_mutex_lock(&ref_count_lock);
    --sp->ref_count;
    pthread_mutex_unlock(&ref_count_lock);
}

void
inc_ref_count(struct rtpp_session *sp)
{
    pthread_mutex_lock(&ref_count_lock);
    ++sp->ref_count;
    pthread_mutex_unlock(&ref_count_lock);
}

struct session_queue_item *
alloc_session_queue_item()
{
    struct session_queue_item *ret;

    pthread_mutex_lock(&session_queue_item_pool_lock);
    while (session_queue_item_pool == NULL) {
        pthread_cond_wait(&session_queue_item_pool_cv, &session_queue_item_pool_lock);
    }
    ret = session_queue_item_pool;
    session_queue_item_pool = ret->next;
    pthread_mutex_unlock(&session_queue_item_pool_lock);
    return ret;
}

void
free_session_queue_item(struct session_queue_item *it)
{
    pthread_mutex_lock(&session_queue_item_pool_lock);
    it->next = session_queue_item_pool;
    session_queue_item_pool = it;
    pthread_mutex_unlock(&session_queue_item_pool_lock);
    pthread_cond_signal(&session_queue_item_pool_cv);
}

void
append_session_later(struct cfg *cf, struct rtpp_session *sp, int index)
{
    struct session_queue_item *it;

    it = alloc_session_queue_item();
    it->session = sp;
    it->index = index;

    it->next = append_buffer;
    append_buffer = it;
    if (append_buffer_last_item == NULL)
        append_buffer_last_item = it;
}

void
append_session_commit(struct cfg *cf)
{
    pthread_mutex_lock(&session_queue_lock);
    append_buffer_last_item->next = session_append_queue;
    session_append_queue = append_buffer;
    pthread_mutex_unlock(&session_queue_lock);
    append_buffer = append_buffer_last_item = NULL;
}

static void
append_session(struct cfg *cf, struct rtpp_session *sp, int index)
{
    cf->sessions[cf->nsessions] = sp;
    cf->pfds[cf->nsessions].fd = sp->fds[index];
    cf->pfds[cf->nsessions].events = POLLIN;
    cf->pfds[cf->nsessions].revents = 0;
    sp->sidx[index] = cf->nsessions;
    cf->nsessions++;
}

void
process_session_queue(struct cfg *cf)
{
    struct session_queue_item *append_it;
    struct session_queue_item *remove_it;
    struct session_queue_item *tmp;

    pthread_mutex_lock(&session_queue_lock);
    append_it = session_append_queue;
    remove_it = session_remove_queue;
    session_append_queue = session_remove_queue = NULL;
    pthread_mutex_unlock(&session_queue_lock);

    while (append_it != NULL) {
        append_session(cf, append_it->session, append_it->index);
        tmp = append_it;
        append_it = append_it->next;
        free_session_queue_item(tmp);
    }

    while (remove_it != NULL) {
        dec_ref_count(remove_it->session); /* release the remove request */
        remove_session(cf, remove_it->session);
        tmp = remove_it;
        remove_it = remove_it->next;
        free_session_queue_item(tmp);
    }
}

int
remove_session_later(struct cfg *cf, struct rtpp_session *sp)
{
    struct session_queue_item *it;

    it = alloc_session_queue_item();
    it->session = sp;

    pthread_mutex_lock(&session_queue_lock);
    it->next = session_remove_queue;
    session_remove_queue = it;
    pthread_mutex_unlock(&session_queue_lock);

    return 0;
}

void *
session_cleaner(void *arg)
{
    struct cfg *cf = (struct cfg *) arg;
    pthread_mutex_lock(&session_cleaner_lock);
    while (1) {
        pthread_cond_wait(&session_cleaner_cv, &session_cleaner_lock);
        free_sessions(cf);
    }
    /* Not reached */
    pthread_mutex_unlock(&session_cleaner_lock);
}

void
free_session(struct cfg *cf, struct rtpp_session *sp)
{
    int i;

    for (i = 0; i < 2; i++) {
	if (sp->addr[i] != NULL)
	    free(sp->addr[i]);
	if (sp->prev_addr[i] != NULL)
	    free(sp->prev_addr[i]);
	if (sp->rtcp->addr[i] != NULL)
	    free(sp->rtcp->addr[i]);
	if (sp->rtcp->prev_addr[i] != NULL)
	    free(sp->rtcp->prev_addr[i]);
	if (sp->rtps[i] != NULL) {
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
}

void
free_session_later(struct cfg *cf, struct rtpp_session *sp)
{
    pthread_mutex_lock(&free_queue_lock);
    sp->free_queue_next = free_sessions_queue;
    free_sessions_queue = sp;
    pthread_mutex_unlock(&free_queue_lock);
    pthread_cond_signal(&session_cleaner_cv);
}

void
free_sessions(struct cfg *cf)
{
    struct rtpp_session *sp;
    struct rtpp_session *tmp;
    struct rtpp_session *keep = NULL;

    pthread_mutex_lock(&free_queue_lock);
    sp = free_sessions_queue;
    while (sp != NULL) {
        if (sp->ref_count > 0) {
            tmp = sp->free_queue_next;
            sp->free_queue_next = keep;
            keep = sp;
            sp = tmp;
        }
        else {
            tmp = sp;
            if (all_sessions == sp) {
                all_sessions = sp->all_sessions_next;
                if (all_sessions != NULL)
                    all_sessions->all_sessions_prev = NULL;
            }
            else {
                sp->all_sessions_prev->all_sessions_next = sp->all_sessions_next;
                if (sp->all_sessions_next != NULL)
                    sp->all_sessions_next->all_sessions_prev = sp->all_sessions_prev;
            }
            free_session(cf, sp);
            sp = tmp->free_queue_next;
        }
    }
    free_sessions_queue = keep;
    pthread_mutex_unlock(&free_queue_lock);
}

void
remove_session(struct cfg *cf, struct rtpp_session *sp)
{
    int i;

    if (sp->removed)
        return;

    rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped", sp->pcount[0], sp->pcount[1],
      sp->pcount[2], sp->pcount[3]);
    rtpp_log_write(RTPP_LOG_INFO, sp->log, "RTCP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped", sp->rtcp->pcount[0],
      sp->rtcp->pcount[1], sp->rtcp->pcount[2], sp->rtcp->pcount[3]);
    rtpp_log_write(RTPP_LOG_INFO, sp->log, "session on ports %d/%d is cleaned up",
      sp->ports[0], sp->ports[1]);
    for (i = 0; i < 2; i++) {
	if (sp->fds[i] != -1) {
	    close(sp->fds[i]);
	    assert(cf->sessions[sp->sidx[i]] == sp);
	    cf->sessions[sp->sidx[i]] = NULL;
	    assert(cf->pfds[sp->sidx[i]].fd == sp->fds[i]);
	    cf->pfds[sp->sidx[i]].fd = -1;
	    cf->pfds[sp->sidx[i]].events = 0;
	}
	if (sp->rtcp->fds[i] != -1) {
	    close(sp->rtcp->fds[i]);
	    assert(cf->sessions[sp->rtcp->sidx[i]] == sp->rtcp);
	    cf->sessions[sp->rtcp->sidx[i]] = NULL;
	    assert(cf->pfds[sp->rtcp->sidx[i]].fd == sp->rtcp->fds[i]);
	    cf->pfds[sp->rtcp->sidx[i]].fd = -1;
	    cf->pfds[sp->rtcp->sidx[i]].events = 0;
	}
	if (sp->rrcs[i] != NULL) {
	    rclose(sp, sp->rrcs[i], 1);
            if (sp->record_single_file != 0) {
                sp->rtcp->rrcs[i] = NULL;
                sp->rrcs[NOT(i)] = NULL;
                sp->rtcp->rrcs[NOT(i)] = NULL;
            }
        }
	if (sp->rtcp->rrcs[i] != NULL)
	    rclose(sp, sp->rtcp->rrcs[i], 1);
	if (sp->rtps[i] != NULL) {
	    cf->rtp_servers[sp->sridx] = NULL;
	}
    }
    cf->sessions_active--;

    sp->removed = 1;
    dec_ref_count(sp); /* release the session from the cfg->sessions array */
    free_session_later(cf, sp);
}

int
compare_session_tags(char *tag1, char *tag0, unsigned *medianum_p)
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
find_stream(struct cfg *cf, char *call_id, char *from_tag, char *to_tag,
  struct rtpp_session **spp)
{
    char *cp1, *cp2;

    for (*spp = session_findfirst(cf, call_id); *spp != NULL; *spp = session_findnext(*spp)) {
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

static void
reconnect_timeout_handler(struct rtpp_session *sp, struct rtpp_timeout_handler *th)
{
    struct sockaddr_un remote;

    assert(th->socket_name != NULL && th->connected == 0);

    if (th->fd == -1) {
        rtpp_log_write(RTPP_LOG_DBUG, sp->log, "connecting timeout socket");
    } else {
        rtpp_log_write(RTPP_LOG_DBUG, sp->log, "reconnecting timeout socket");
        close(th->fd);
    }
    th->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (th->fd == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't create timeout socket");
        return;
    }
    memset(&remote, '\0', sizeof(remote));
    remote.sun_family = AF_LOCAL;
    strncpy(remote.sun_path, th->socket_name, sizeof(remote.sun_path) - 1);
#if defined(HAVE_SOCKADDR_SUN_LEN)
    remote.sun_len = strlen(remote.sun_path);
#endif
    if (connect(th->fd, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "can't connect to timeout socket");
    } else {
        th->connected = 1;
    }
}

void
do_timeout_notification(struct rtpp_session *sp, int retries)
{
    int result, len;
    struct rtpp_timeout_handler *th = sp->timeout_data.handler;

    if (th == NULL)
	return;

    if (th->connected == 0) {
        reconnect_timeout_handler(sp, th);

        /* If connect fails, no notification will be sent */
        if (th->connected == 0) {
            rtpp_log_write(RTPP_LOG_ERR, sp->log, "unable to send timeout notification");
            return;
        }
    }

    if (sp->timeout_data.notify_tag == NULL) {
        len = snprintf(th->notify_buf, sizeof(th->notify_buf), "%d %d\n",
          sp->ports[0], sp->ports[1]);
    } else {
        len = snprintf(th->notify_buf, sizeof(th->notify_buf), "%s\n",
          sp->timeout_data.notify_tag);
    }
    assert(len < sizeof(th->notify_buf));

    do {
        result = send(th->fd, th->notify_buf, len, 0);
    } while (len == -1 && errno == EINTR);

    if (result < 0) {
        th->connected = 0;
        rtpp_log_ewrite(RTPP_LOG_ERR, sp->log, "failed to send timeout notification");
        if (retries > 0)
            do_timeout_notification(sp, retries - 1);
    }
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

void
lock_session_cleaner()
{
    pthread_mutex_lock(&session_cleaner_lock);
}

void
unlock_session_cleaner()
{
    pthread_mutex_unlock(&session_cleaner_lock);
}

void
register_session(struct rtpp_session *sp)
{
    if (all_sessions != NULL)
        all_sessions->all_sessions_prev = sp;
    sp->all_sessions_next = all_sessions;
    all_sessions = sp;
    sp->all_sessions_prev = NULL;
}
