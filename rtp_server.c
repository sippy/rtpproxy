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

#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>

#include "rtp_server.h"
#include "rtpp_util.h"
#include "rtp.h"

static pthread_mutex_t rtp_server_queue_lock;
static struct session_queue_item *append_server_queue;
static struct session_queue_item *noplay_queue;

struct rtp_server *
rtp_server_new(const char *name, rtp_type_t codec, int loop)
{
    struct rtp_server *rp;
    int fd;
    char path[PATH_MAX + 1];

    sprintf(path, "%s.%d", name, codec);
    fd = open(path, O_RDONLY);
    if (fd == -1)
	return NULL;

    rp = malloc(sizeof(*rp));
    if (rp == NULL)
	return NULL;

    memset(rp, 0, sizeof(*rp));

    rp->btime = -1;
    rp->fd = fd;
    rp->loop = (loop > 0) ? loop - 1 : loop;

    rp->rtp = (rtp_hdr_t *)rp->buf;
    rp->rtp->version = 2;
    rp->rtp->p = 0;
    rp->rtp->x = 0;
    rp->rtp->cc = 0;
    rp->rtp->m = 1;
    rp->rtp->pt = codec;
    rp->rtp->ts = 0;
    rp->rtp->seq = 0;
    rp->rtp->ssrc = random();
    rp->pload = rp->buf + RTP_HDR_LEN(rp->rtp);

    return rp;
}

void
rtp_server_free(struct rtp_server *rp)
{

    close(rp->fd);
    free(rp);
}

int
rtp_server_get(struct rtp_server *rp, double dtime)
{
    uint32_t ts;
    int rlen, rticks, bytes_per_frame, ticks_per_frame, number_of_frames;

    if (rp->btime == -1)
	rp->btime = dtime;

    ts = ntohl(rp->rtp->ts);

    if (rp->btime + ((double)ts / RTPS_SRATE) > dtime)
	return RTPS_LATER;

    switch (rp->rtp->pt) {
    case RTP_PCMU:
    case RTP_PCMA:
	bytes_per_frame = 8;
	ticks_per_frame = 1;
	break;

    case RTP_G729:
	/* 10 ms per 8 kbps G.729 frame */
	bytes_per_frame = 10;
	ticks_per_frame = 10;
	break;

    case RTP_G723:
	/* 30 ms per 6.3 kbps G.723 frame */
	bytes_per_frame = 24;
	ticks_per_frame = 30;
	break;

    case RTP_GSM:
	/* 20 ms per 13 kbps GSM frame */
	bytes_per_frame = 33;
	ticks_per_frame = 20;
	break;

    default:
	return RTPS_ERROR;
    }

    number_of_frames = RTPS_TICKS_MIN / ticks_per_frame;
    if (RTPS_TICKS_MIN % ticks_per_frame != 0)
	number_of_frames++;

    rlen = bytes_per_frame * number_of_frames;
    rticks = ticks_per_frame * number_of_frames;

    if (read(rp->fd, rp->pload, rlen) != rlen) {
	if (rp->loop == 0 || lseek(rp->fd, 0, SEEK_SET) == -1 ||
	  read(rp->fd, rp->pload, rlen) != rlen)
	    return RTPS_EOF;
	if (rp->loop != -1)
	    rp->loop -= 1;
    }

    if (rp->rtp->m != 0 && ntohs(rp->rtp->seq) != 0) {
	rp->rtp->m = 0;
    }

    rp->rtp->ts = htonl(ts + (RTPS_SRATE * rticks / 1000));
    rp->rtp->seq = htons(ntohs(rp->rtp->seq) + 1);

    return (rp->pload - rp->buf) + rlen;
}

void
append_server_later(struct cfg *cf, struct rtpp_session *spa, int idx, struct rtp_server *server)
{
    struct session_queue_item *it;

    it = alloc_session_queue_item();
    pthread_mutex_lock(&rtp_server_queue_lock);
    it->session = spa;
    it->index = idx;
    it->server = server;
    it->next = append_server_queue;
    append_server_queue = it;
    pthread_mutex_unlock(&rtp_server_queue_lock);
}

void
append_server(struct cfg *cf, struct rtpp_session *sp, int idx, struct rtp_server *server)
{
    if (sp->rtps[idx])
        rtp_server_free(sp->rtps[idx]);

    sp->rtps[idx] = server;
    if (sp->sridx == -1) {
        cf->rtp_servers[cf->rtp_nsessions] = sp;
        sp->sridx = cf->rtp_nsessions;
        cf->rtp_nsessions++;
    }
}

void
handle_noplay_later(struct cfg *cf, struct rtpp_session *spa, int idx)
{
    struct session_queue_item *it;

    it = alloc_session_queue_item();
    pthread_mutex_lock(&rtp_server_queue_lock);
    it->session = spa;
    it->index = idx;
    it->next = noplay_queue;
    noplay_queue = it;
    pthread_mutex_unlock(&rtp_server_queue_lock);
}

static void
handle_noplay(struct cfg *cf, struct rtpp_session *spa, int idx)
{
    if (spa->rtps[idx] != NULL) {
	rtp_server_free(spa->rtps[idx]);
	spa->rtps[idx] = NULL;
	rtpp_log_write(RTPP_LOG_INFO, spa->log,
	  "stopping player at port %d", spa->ports[idx]);
	if (spa->rtps[0] == NULL && spa->rtps[1] == NULL) {
	    assert(cf->rtp_servers[spa->sridx] == spa);
	    cf->rtp_servers[spa->sridx] = NULL;
	    spa->sridx = -1;
            dec_ref_count(spa);
	}
    }
}

void
process_rtp_server_queue(struct cfg *cf)
{
    struct session_queue_item *noplay_it;
    struct session_queue_item *append_it;
    struct session_queue_item *tmp;

    pthread_mutex_lock(&rtp_server_queue_lock);
    noplay_it = noplay_queue;
    noplay_queue = NULL;
    append_it = append_server_queue;
    append_server_queue = NULL;
    pthread_mutex_unlock(&rtp_server_queue_lock);

    while (noplay_it != NULL) {
        handle_noplay(cf, noplay_it->session, noplay_it->index);
        tmp = noplay_it;
        dec_ref_count(tmp->session);
        noplay_it = noplay_it->next;
        free_session_queue_item(tmp);
    }
    
    while (append_it != NULL) {
        append_server(cf, append_it->session, append_it->index, append_it->server);
        tmp = append_it;
        append_it = append_it->next;
        free_session_queue_item(tmp);
    }
}

void
rtp_server_storage_init()
{
    pthread_mutex_init(&rtp_server_queue_lock, NULL);
}
