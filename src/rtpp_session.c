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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_hash_table.h"
#include "rtpp_math.h"
#include "rtpp_pthread.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_ttl.h"
#include "rtpp_refcnt.h"

struct rtpp_session_priv
{
    struct rtpp_session pub;
    struct rtpp_sessinfo *sessinfo;
    struct rtpp_hash_table *sessions_ht;
    void *rco[0];
};

#define PUB2PVT(pubp) \
  ((struct rtpp_session_priv *)((char *)(pubp) - offsetof(struct rtpp_session_priv, pub)))

static void rtpp_session_dtor(struct rtpp_session_priv *);

struct rtpp_session *
session_findfirst(struct cfg *cf, const char *call_id)
{
    struct rtpp_session *sp;
    struct rtpp_hash_table_entry *he;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

    he = CALL_METHOD(cf->stable->sessions_ht, findfirst, call_id, (void **)&sp);
    if (he == NULL) {
        return (NULL);
    }
    return (sp);
}

struct rtpp_session *
session_findnext(struct cfg *cf, struct rtpp_session *psp)
{
    struct rtpp_session *sp;
    struct rtpp_hash_table_entry *he;

    /* Make sure structure is properly locked */
    assert(rtpp_mutex_islocked(&cf->glock) == 1);

    he = CALL_METHOD(cf->stable->sessions_ht, findnext, psp->hte, (void **)&sp); 
    if (he == NULL) {
        return (NULL);
    }
    return (sp);
}

struct rtpp_session *
rtpp_session_ctor(struct rtpp_cfg_stable *cfs, struct common_cmd_args *ccap,
  double dtime, struct sockaddr **lia, int weak, int lport,
  struct rtpp_socket **fds)
{
    struct rtpp_session_priv *pvt;
    struct rtpp_session *pub;
    struct rtpp_log *log;
    int i;
    char *cp;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_session_priv) + rtpp_refcnt_osize());
    if (pvt == NULL) {
        goto e0;
    }

    pub = &(pvt->pub);
    rtpp_gen_uid(&pub->seuid);

    log = rtpp_log_ctor(cfs, "rtpproxy", ccap->call_id, 0);
    if (log == NULL) {
        goto e1;
    }
    CALL_METHOD(log, setlevel, cfs->log_level);
    pub->rtp = rtpp_pipe_ctor(pub->seuid, cfs->rtp_streams_wrt,
      cfs->servers_wrt, log, cfs->rtpp_stats, SESS_RTP);
    if (pub->rtp == NULL) {
        goto e2;
    }
    /* spb is RTCP twin session for this one. */
    pub->rtcp = rtpp_pipe_ctor(pub->seuid, cfs->rtcp_streams_wrt,
      cfs->servers_wrt, log, cfs->rtpp_stats, SESS_RTCP);
    if (pub->rtcp == NULL) {
        goto e3;
    }
    pub->init_ts = dtime;
    pub->call_id = strdup(ccap->call_id);
    if (pub->call_id == NULL) {
        goto e4;
    }
    pub->tag = strdup(ccap->from_tag);
    if (pub->tag == NULL) {
        goto e5;
    }
    pub->tag_nomedianum = strdup(ccap->from_tag);
    if (pub->tag_nomedianum == NULL) {
        goto e6;
    }
    cp = strrchr(pub->tag_nomedianum, ';');
    if (cp != NULL)
        *cp = '\0';
    for (i = 0; i < 2; i++) {
        pub->rtp->stream[i]->laddr = lia[i];
        pub->rtcp->stream[i]->laddr = lia[i];
    }
    if (weak) {
        pub->rtp->stream[0]->weak = 1;
    } else {
        pub->strong = 1;
    }

    pub->rtp->stream[0]->fd = fds[0];
    pub->rtcp->stream[0]->fd = fds[1];
    pub->rtp->stream[0]->port = lport;
    pub->rtcp->stream[0]->port = lport + 1;
    for (i = 0; i < 2; i++) {
        if (i == 0 || cfs->ttl_mode == TTL_INDEPENDENT) {
            pub->rtp->stream[i]->ttl = rtpp_ttl_ctor(cfs->max_setup_ttl);
            if (pub->rtp->stream[i]->ttl == NULL) {
                goto e7;
            }
        } else {
            pub->rtp->stream[i]->ttl = pub->rtp->stream[0]->ttl;
            CALL_METHOD(pub->rtp->stream[0]->ttl->rcnt, incref);
        }
        /* RTCP shares the same TTL */
        pub->rtcp->stream[i]->ttl = pub->rtp->stream[i]->ttl;
        CALL_METHOD(pub->rtp->stream[i]->ttl->rcnt, incref);
    }
    for (i = 0; i < 2; i++) {
        pub->rtp->stream[i]->stuid_rtcp = pub->rtcp->stream[i]->stuid;
        pub->rtcp->stream[i]->stuid_rtp = pub->rtp->stream[i]->stuid;
    }

    pub->hte = CALL_METHOD(cfs->sessions_ht, append, pub->call_id, pub);
    if (pub->hte == NULL) {
        goto e7;
    }

    pub->rcnt = rtpp_refcnt_ctor_pa(&pvt->rco[0], pvt,
      (rtpp_refcnt_dtor_t)&rtpp_session_dtor);
    if (pub->rcnt == NULL) {
        goto e8;
    }

    pvt->pub.rtpp_stats = cfs->rtpp_stats;
    pvt->pub.log = log;
    pvt->sessinfo = cfs->sessinfo;
    pvt->sessions_ht = cfs->sessions_ht;

    CALL_METHOD(cfs->sessinfo, append, pub, 0);

    return (&pvt->pub);

e8:
    CALL_METHOD(cfs->sessions_ht, remove, pub->call_id, pub->hte);
e7:
    free(pub->tag_nomedianum);
e6:
    free(pub->tag);
e5:
    free(pub->call_id);
e4:
    CALL_METHOD(pub->rtcp->rcnt, decref);
e3:
    CALL_METHOD(pub->rtp->rcnt, decref);
e2:
    CALL_METHOD(log->rcnt, decref);
e1:
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_session_dtor(struct rtpp_session_priv *pvt)
{
    struct rtpps_pcount pcnts;
    int i;
    double session_time;
    struct rtpp_session *pub;

    pub = &(pvt->pub);
    session_time = getdtime() - pub->init_ts;

    CALL_METHOD(pub->rtp->pcount, get_stats, &pcnts);
    RTPP_LOG(pub->log, RTPP_LOG_INFO, "RTP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored", pub->rtp->stream[0]->npkts_in,
      pub->rtp->stream[1]->npkts_in, pcnts.nrelayed, pcnts.ndropped, pcnts.nignored);
    CALL_METHOD(pub->rtcp->pcount, get_stats, &pcnts);
    RTPP_LOG(pub->log, RTPP_LOG_INFO, "RTCP stats: %lu in from callee, %lu "
      "in from caller, %lu relayed, %lu dropped, %lu ignored", pub->rtcp->stream[0]->npkts_in,
      pub->rtcp->stream[1]->npkts_in, pcnts.nrelayed, pcnts.ndropped, pcnts.nignored);
    if (pub->complete != 0) {
        if (pub->rtp->stream[0]->npkts_in == 0 && pub->rtp->stream[1]->npkts_in == 0) {
            CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_nortp", 1);
        } else if (pub->rtp->stream[0]->npkts_in == 0 || pub->rtp->stream[1]->npkts_in == 0) {
            CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_owrtp", 1);
        }
        if (pub->rtcp->stream[0]->npkts_in == 0 && pub->rtcp->stream[1]->npkts_in == 0) {
            CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_nortcp", 1);
        } else if (pub->rtcp->stream[0]->npkts_in == 0 || pub->rtcp->stream[1]->npkts_in == 0) {
            CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_owrtcp", 1);
        }
    }
    RTPP_LOG(pub->log, RTPP_LOG_INFO, "session on ports %d/%d is cleaned up",
      pub->rtp->stream[0]->port, pub->rtp->stream[1]->port);
    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->sessinfo, remove, pub, i);
    }
    CALL_METHOD(pvt->sessions_ht, remove, pub->call_id, pub->hte);
    CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_destroyed", 1);
    CALL_METHOD(pub->rtpp_stats, updatebyname_d, "total_duration",
      session_time);

    CALL_METHOD(pvt->pub.log->rcnt, decref);
    if (pvt->pub.timeout_data.notify_tag != NULL)
        free(pvt->pub.timeout_data.notify_tag);
    if (pvt->pub.call_id != NULL)
        free(pvt->pub.call_id);
    if (pvt->pub.tag != NULL)
        free(pvt->pub.tag);
    if (pvt->pub.tag_nomedianum != NULL)
        free(pvt->pub.tag_nomedianum);

    CALL_METHOD(pvt->pub.rtcp->rcnt, decref);
    CALL_METHOD(pvt->pub.rtp->rcnt, decref);
    free(pvt);
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
