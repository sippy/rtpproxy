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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_analyzer.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_hash_table.h"
#include "rtpp_mallocs.h"
#include "rtpp_module_if.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_ttl.h"
#include "rtpp_refcnt.h"

struct rtpp_session_priv
{
    struct rtpp_session pub;
    struct rtpp_sessinfo *sessinfo;
    struct rtpp_module_if *modules_cf;
    struct rtpp_acct *acct;
};

#define PUB2PVT(pubp) \
  ((struct rtpp_session_priv *)((char *)(pubp) - offsetof(struct rtpp_session_priv, pub)))

static void rtpp_session_dtor(struct rtpp_session_priv *);

struct rtpp_session *
rtpp_session_ctor(struct rtpp_cfg_stable *cfs, struct common_cmd_args *ccap,
  double dtime, struct sockaddr **lia, int weak, int lport,
  struct rtpp_socket **fds)
{
    struct rtpp_session_priv *pvt;
    struct rtpp_session *pub;
    struct rtpp_log *log;
    struct rtpp_refcnt *rcnt;
    int i;
    char *cp;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_session_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }

    pub = &(pvt->pub);
    pub->rcnt = rcnt;
    rtpp_gen_uid(&pub->seuid);

    log = rtpp_log_ctor(cfs, "rtpproxy", ccap->call_id, 0);
    if (log == NULL) {
        goto e1;
    }
    CALL_METHOD(log, setlevel, cfs->log_level);
    pub->rtp = rtpp_pipe_ctor(pub->seuid, cfs->rtp_streams_wrt,
      cfs->servers_wrt, log, cfs->rtpp_stats, PIPE_RTP);
    if (pub->rtp == NULL) {
        goto e2;
    }
    /* spb is RTCP twin session for this one. */
    pub->rtcp = rtpp_pipe_ctor(pub->seuid, cfs->rtcp_streams_wrt,
      cfs->servers_wrt, log, cfs->rtpp_stats, PIPE_RTCP);
    if (pub->rtcp == NULL) {
        goto e3;
    }
    pvt->acct = rtpp_acct_ctor(pub->seuid);
    if (pvt->acct == NULL) {
        goto e4;
    }
    pvt->acct->init_ts = dtime;
    pub->call_id = strdup(ccap->call_id);
    if (pub->call_id == NULL) {
        goto e5;
    }
    pub->tag = strdup(ccap->from_tag);
    if (pub->tag == NULL) {
        goto e6;
    }
    pub->tag_nomedianum = strdup(ccap->from_tag);
    if (pub->tag_nomedianum == NULL) {
        goto e7;
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

    pub->rtp->stream[0]->port = lport;
    pub->rtcp->stream[0]->port = lport + 1;
    for (i = 0; i < 2; i++) {
        if (i == 0 || cfs->ttl_mode == TTL_INDEPENDENT) {
            pub->rtp->stream[i]->ttl = rtpp_ttl_ctor(cfs->max_setup_ttl);
            if (pub->rtp->stream[i]->ttl == NULL) {
                goto e8;
            }
        } else {
            pub->rtp->stream[i]->ttl = pub->rtp->stream[0]->ttl;
            CALL_SMETHOD(pub->rtp->stream[0]->ttl->rcnt, incref);
        }
        /* RTCP shares the same TTL */
        pub->rtcp->stream[i]->ttl = pub->rtp->stream[i]->ttl;
        CALL_SMETHOD(pub->rtp->stream[i]->ttl->rcnt, incref);
    }
    for (i = 0; i < 2; i++) {
        pub->rtp->stream[i]->stuid_rtcp = pub->rtcp->stream[i]->stuid;
        pub->rtcp->stream[i]->stuid_rtp = pub->rtp->stream[i]->stuid;
    }

    pvt->pub.rtpp_stats = cfs->rtpp_stats;
    pvt->pub.log = log;
    pvt->sessinfo = cfs->sessinfo;
    if (cfs->modules_cf != NULL) {
        CALL_SMETHOD(cfs->modules_cf->rcnt, incref);
        pvt->modules_cf = cfs->modules_cf;
    }

    CALL_METHOD(cfs->sessinfo, append, pub, 0, fds);

    CALL_SMETHOD(pub->rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_session_dtor,
      pvt);
    return (&pvt->pub);

e8:
    free(pub->tag_nomedianum);
e7:
    free(pub->tag);
e6:
    free(pub->call_id);
e5:
    CALL_SMETHOD(pvt->acct->rcnt, decref);
e4:
    CALL_SMETHOD(pub->rtcp->rcnt, decref);
e3:
    CALL_SMETHOD(pub->rtp->rcnt, decref);
e2:
    CALL_SMETHOD(log->rcnt, decref);
e1:
    CALL_SMETHOD(pub->rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

#define MT2RT_NZ(mt) ((mt) == 0.0 ? 0.0 : dtime2rtime(mt))
#define DRTN_NZ(bmt, emt) ((emt) == 0.0 || (bmt) == 0.0 ? 0.0 : ((emt) - (bmt)))

static void
rtpp_session_dtor(struct rtpp_session_priv *pvt)
{
    int i;
    double session_time;
    struct rtpp_session *pub;

    pub = &(pvt->pub);
    pvt->acct->destroy_ts = getdtime();
    session_time = pvt->acct->destroy_ts - pvt->acct->init_ts;

    CALL_METHOD(pub->rtp, get_stats, &pvt->acct->rtp);
    CALL_METHOD(pub->rtcp, get_stats, &pvt->acct->rtcp);
    if (pub->complete != 0) {
        CALL_METHOD(pub->rtp, upd_cntrs, &pvt->acct->rtp);
        CALL_METHOD(pub->rtcp, upd_cntrs, &pvt->acct->rtcp);
    }
    RTPP_LOG(pub->log, RTPP_LOG_INFO, "session on ports %d/%d is cleaned up",
      pub->rtp->stream[0]->port, pub->rtp->stream[1]->port);
    for (i = 0; i < 2; i++) {
        CALL_METHOD(pvt->sessinfo, remove, pub, i);
    }
    CALL_METHOD(pub->rtpp_stats, updatebyname, "nsess_destroyed", 1);
    CALL_METHOD(pub->rtpp_stats, updatebyname_d, "total_duration",
      session_time);
    if (pvt->modules_cf != NULL) {
        pvt->acct->call_id = pvt->pub.call_id;
        pvt->pub.call_id = NULL;
        pvt->acct->from_tag = pvt->pub.tag;
        pvt->pub.tag = NULL;
        CALL_METHOD(pub->rtp->stream[0]->analyzer, get_stats, \
          pvt->acct->rasto);
        CALL_METHOD(pub->rtp->stream[1]->analyzer, get_stats, \
          pvt->acct->rasta);
        CALL_METHOD(pub->rtp->stream[0]->analyzer, get_jstats, \
          pvt->acct->jrasto);
        CALL_METHOD(pub->rtp->stream[1]->analyzer, get_jstats, \
          pvt->acct->jrasta);

        CALL_METHOD(pvt->modules_cf, do_acct, pvt->acct);
        CALL_SMETHOD(pvt->modules_cf->rcnt, decref);
    }
    CALL_SMETHOD(pvt->acct->rcnt, decref);

    CALL_SMETHOD(pvt->pub.log->rcnt, decref);
    if (pvt->pub.timeout_data.notify_tag != NULL)
        free(pvt->pub.timeout_data.notify_tag);
    if (pvt->pub.call_id != NULL)
        free(pvt->pub.call_id);
    if (pvt->pub.tag != NULL)
        free(pvt->pub.tag);
    if (pvt->pub.tag_nomedianum != NULL)
        free(pvt->pub.tag_nomedianum);

    CALL_SMETHOD(pvt->pub.rtcp->rcnt, decref);
    CALL_SMETHOD(pvt->pub.rtp->rcnt, decref);
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

struct session_match_args {
    const char *from_tag;
    const char *to_tag;
    struct rtpp_session *sp;
    int rval;
};

static int
rtpp_session_ematch(void *dp, void *ap)
{
    struct rtpp_session *rsp;
    struct session_match_args *map;
    const char *cp1, *cp2;

    rsp = (struct rtpp_session *)dp;
    map = (struct session_match_args *)ap;

    if (strcmp(rsp->tag, map->from_tag) == 0) {
        map->rval = 0;
        goto found;
    }
    if (map->to_tag != NULL) {
        switch (compare_session_tags(rsp->tag, map->to_tag, NULL)) {
        case 1:
            /* Exact tag match */
            map->rval = 1;
            goto found;

        case 2:
            /*
             * Reverse tag match without medianum. Medianum is always
             * applied to the from tag, verify that.
             */
            cp1 = strrchr(rsp->tag, ';');
            cp2 = strrchr(map->from_tag, ';');
            if (cp2 != NULL && strcmp(cp1, cp2) == 0) {
                map->rval = 1;
                goto found;
            }
            break;

        default:
            break;
        }
    }
    return (RTPP_HT_MATCH_CONT);

found:
    CALL_SMETHOD(rsp->rcnt, incref);
    RTPP_DBG_ASSERT(map->sp == NULL);
    map->sp = rsp;
    return (RTPP_HT_MATCH_BRK);
}

int
find_stream(struct cfg *cf, const char *call_id, const char *from_tag,
  const char *to_tag, struct rtpp_session **spp)
{
    struct session_match_args ma;

    memset(&ma, '\0', sizeof(ma));
    ma.from_tag = from_tag;
    ma.to_tag = to_tag;
    ma.rval = -1;

    CALL_METHOD(cf->stable->sessions_ht, foreach_key, call_id,
      rtpp_session_ematch, &ma);
    if (ma.rval != -1) {
        *spp = ma.sp;
    }
    return ma.rval;
}
