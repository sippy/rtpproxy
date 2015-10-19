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
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_hash_table.h"
#include "rtpp_math.h"
#include "rtpp_pthread.h"
#include "rtpp_record.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_util.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"

struct rtpp_session_priv
{
    struct rtpp_session_obj pub;
    struct rtpp_weakref_obj *streams_wrt;
    int session_type;
    void *rco[0];
};

#define PUB2PVT(pubp) \
  ((struct rtpp_session_priv *)((char *)(pubp) - offsetof(struct rtpp_session_priv, pub)))

static void rtpp_session_dtor(struct rtpp_session_priv *);

struct rtpp_session_obj *
session_findfirst(struct cfg *cf, const char *call_id)
{
    struct rtpp_session_obj *sp;
    struct rtpp_hash_table_entry *he;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

    he = CALL_METHOD(cf->stable->sessions_ht, findfirst, call_id, (void **)&sp);
    if (he == NULL) {
        return (NULL);
    }
    return (sp);
}

struct rtpp_session_obj *
session_findnext(struct cfg *cf, struct rtpp_session_obj *psp)
{
    struct rtpp_session_obj *sp;
    struct rtpp_hash_table_entry *he;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

    he = CALL_METHOD(cf->stable->sessions_ht, findnext, psp->hte, (void **)&sp); 
    if (he == NULL) {
        return (NULL);
    }
    return (sp);
}

struct rtpp_session_obj *
rtpp_session_ctor(struct rtpp_cfg_stable *cfs, struct rtpp_log_obj *log, int session_type)
{
    struct rtpp_session_priv *pvt;
    int i;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_session_priv) + rtpp_refcnt_osize());
    if (pvt == NULL) {
        goto e0;
    }

    if (session_type == SESS_RTP) {
        pvt->streams_wrt = cfs->rtp_streams_wrt;
    } else {
        pvt->streams_wrt = cfs->rtcp_streams_wrt;
    }

    for (i = 0; i < 2; i++) {
        pvt->pub.stream[i] = rtpp_stream_ctor(log, cfs->servers_wrt,
          cfs->rtpp_stats, i, session_type);
        if (pvt->pub.stream[i] == NULL) {
            goto e1;
        }
        if (CALL_METHOD(pvt->streams_wrt, reg, pvt->pub.stream[i]->rcnt,
          pvt->pub.stream[i]->stuid) != 0) {
            goto e1;
        }
    }
    pvt->pub.rcnt = rtpp_refcnt_ctor_pa(&pvt->rco[0], pvt,
      (rtpp_refcnt_dtor_t)&rtpp_session_dtor);
    if (pvt->pub.rcnt == NULL) {
        goto e1;
    }
    pvt->session_type = session_type;
    pvt->pub.rtpp_stats = cfs->rtpp_stats;
    pvt->pub.log = log;
    CALL_METHOD(log->rcnt, incref);
    rtpp_gen_uid(&pvt->pub.seuid);
    return (&pvt->pub);

e1:
    for (i = 0; i < 2; i++) {
        if (pvt->pub.stream[i] != NULL) {
            CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
            CALL_METHOD(pvt->pub.stream[i]->rcnt, decref);
        }
    }
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_session_dtor(struct rtpp_session_priv *pvt)
{
    int i;

    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->streams_wrt, unreg, pvt->pub.stream[i]->stuid);
        CALL_METHOD(pvt->pub.stream[i]->rcnt, decref);
    }
    CALL_METHOD(pvt->pub.log->rcnt, decref);
    if (pvt->session_type == SESS_RTCP) {
        free(pvt);
        return;
    }
    if (pvt->pub.timeout_data.notify_tag != NULL)
        free(pvt->pub.timeout_data.notify_tag);
    if (pvt->pub.call_id != NULL)
        free(pvt->pub.call_id);
    if (pvt->pub.tag != NULL)
        free(pvt->pub.tag);
    if (pvt->pub.tag_nomedianum != NULL)
        free(pvt->pub.tag_nomedianum);

    CALL_METHOD(pvt->pub.rtcp->rcnt, decref);
    free(pvt);
}

void
append_session(struct cfg *cf, struct rtpp_session_obj *sp, int index)
{

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

    if (sp->stream[index]->fd != NULL) {
        CALL_METHOD(cf->sessinfo, append, sp, index);
    } else {
	sp->stream[index]->sidx = -1;
    }
}

void
update_sessions(struct cfg *cf, struct rtpp_session_obj *sp, int index, 
  struct rtpp_socket **new_fds)
{
    int rtp_index;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);
    rtp_index = sp->stream[index]->sidx;
    assert(rtp_index > -1);
    assert(sp->rtcp->stream[index]->sidx == rtp_index);
    if (sp->stream[index]->fd != NULL) {
        CALL_METHOD(sp->stream[index]->fd->rcnt, decref);
    }
    sp->stream[index]->fd = new_fds[0];
    cf->sessinfo->pfds_rtp[rtp_index].fd = CALL_METHOD(new_fds[0], getfd);
    cf->sessinfo->pfds_rtp[rtp_index].events = POLLIN;
    cf->sessinfo->pfds_rtp[rtp_index].revents = 0;
    if (sp->rtcp->stream[index]->fd != NULL) {
        CALL_METHOD(sp->rtcp->stream[index]->fd->rcnt, decref);
    }
    sp->rtcp->stream[index]->fd = new_fds[1];
    cf->sessinfo->pfds_rtcp[rtp_index].fd = CALL_METHOD(new_fds[1], getfd);
    cf->sessinfo->pfds_rtcp[rtp_index].events = POLLIN;
    cf->sessinfo->pfds_rtcp[rtp_index].revents = 0;
}

void
remove_session(struct cfg *cf, struct rtpp_session_obj *sp)
{
    int i;
    double session_time;

    session_time = getdtime() - sp->init_ts;
    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);
    assert(rtpp_mutex_islocked(&cf->sessinfo->lock) == 1);

    RTPP_LOG(sp->log, RTPP_LOG_INFO, "RTP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored", sp->stream[0]->npkts_in,
      sp->stream[1]->npkts_in, sp->pcount.nrelayed, sp->pcount.ndropped,
      sp->pcount.nignored);
    RTPP_LOG(sp->log, RTPP_LOG_INFO, "RTCP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored", sp->rtcp->stream[0]->npkts_in,
      sp->rtcp->stream[1]->npkts_in, sp->rtcp->pcount.nrelayed,
      sp->rtcp->pcount.ndropped, sp->rtcp->pcount.nignored);
    if (sp->complete != 0) {
        if (sp->stream[0]->npkts_in == 0 && sp->stream[1]->npkts_in == 0) {
            CALL_METHOD(sp->rtpp_stats, updatebyname, "nsess_nortp", 1);
        } else if (sp->stream[0]->npkts_in == 0 || sp->stream[1]->npkts_in == 0) {
            CALL_METHOD(sp->rtpp_stats, updatebyname, "nsess_owrtp", 1);
        }
        if (sp->rtcp->stream[0]->npkts_in == 0 && sp->rtcp->stream[1]->npkts_in == 0) {
            CALL_METHOD(sp->rtpp_stats, updatebyname, "nsess_nortcp", 1);
        } else if (sp->rtcp->stream[0]->npkts_in == 0 || sp->rtcp->stream[1]->npkts_in == 0) {
            CALL_METHOD(sp->rtpp_stats, updatebyname, "nsess_owrtcp", 1);
        }
    }
    RTPP_LOG(sp->log, RTPP_LOG_INFO, "session on ports %d/%d is cleaned up",
      sp->stream[0]->port, sp->stream[1]->port);
    for (i = 0; i < 2; i++) {
	if (sp->stream[i]->fd != NULL) {
	    assert(cf->sessinfo->sessions[sp->stream[i]->sidx] == sp);
	    cf->sessinfo->sessions[sp->stream[i]->sidx] = NULL;
	    assert(cf->sessinfo->pfds_rtp[sp->stream[i]->sidx].fd == CALL_METHOD(sp->stream[i]->fd, getfd));
	    cf->sessinfo->pfds_rtp[sp->stream[i]->sidx].fd = -1;
	    cf->sessinfo->pfds_rtp[sp->stream[i]->sidx].events = 0;
	}
	if (sp->rtcp->stream[i]->fd != NULL) {
	    assert(cf->sessinfo->pfds_rtcp[sp->rtcp->stream[i]->sidx].fd == CALL_METHOD(sp->rtcp->stream[i]->fd, getfd));
	    cf->sessinfo->pfds_rtcp[sp->rtcp->stream[i]->sidx].fd = -1;
	    cf->sessinfo->pfds_rtcp[sp->rtcp->stream[i]->sidx].events = 0;
	}
	if (sp->stream[i]->rrc != NULL) {
	    rclose(sp->stream[i], sp->stream[i]->rrc, 1);
            if (sp->record_single_file != 0) {
                sp->rtcp->stream[i]->rrc = NULL;
                sp->stream[NOT(i)]->rrc = NULL;
                sp->rtcp->stream[NOT(i)]->rrc = NULL;
            }
        }
	if (sp->rtcp->stream[i]->rrc != NULL)
	    rclose(sp->rtcp->stream[i], sp->rtcp->stream[i]->rrc, 1);
    }
    if (sp->hte != NULL)
        CALL_METHOD(cf->stable->sessions_ht, remove, sp->call_id, sp->hte);
    assert(sp->rtp_seuid == 0);
    CALL_METHOD(cf->stable->sessions_wrt, unreg, sp->seuid);
    cf->sessions_active--;
    CALL_METHOD(sp->rtpp_stats, updatebyname, "nsess_destroyed", 1);
    CALL_METHOD(sp->rtpp_stats, updatebyname_d, "total_duration",
      session_time);
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
  const char *to_tag, struct rtpp_session_obj **spp)
{
    const char *cp1, *cp2;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

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
get_ttl(struct rtpp_session_obj *sp)
{

    switch(sp->ttl_mode) {
    case TTL_UNIFIED:
	return (MAX(sp->stream[0]->ttl, sp->stream[1]->ttl));

    case TTL_INDEPENDENT:
	return (MIN(sp->stream[0]->ttl, sp->stream[1]->ttl));

    default:
	/* Shouldn't happen[tm] */
	break;
    }
    abort();
    return 0;
}
