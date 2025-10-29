/*
 * Copyright (c) 2006-2020 Sippy Software, Inc., http://www.sippysoft.com
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_analyzer.h"
#include "rtpp_command.h"
#include "rtpp_time.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid.h"
#include "rtpp_hash_table.h"
#include "rtpp_list.h"
#include "rtpp_mallocs.h"
#include "rtpp_module_if.h"
#include "rtpp_modman.h"
#include "rtpp_pipe.h"
#include "rtpp_codeptr.h"
#include "rtpp_socket.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_ttl.h"
#include "rtpp_refcnt.h"
#include "rtpp_timeout_data.h"
#include "rtpp_proc_async.h"

struct rtpp_session_priv
{
    struct rtpp_session pub;
    struct rtpp_sessinfo *sessinfo;
    struct rtpp_modman *module_cf;
    struct rtpp_acct *acct;
    struct rtpp_str call_id;
    struct rtpp_str from_tag;
    struct rtpp_str from_tag_nmn;
};

static void rtpp_session_dtor(struct rtpp_session_priv *);

struct rtpp_session *
rtpp_session_ctor(const struct rtpp_session_ctor_args *ap)
{
    struct rtpp_session_priv *pvt;
    struct rtpp_session *pub;
    struct rtpp_log *log;
    struct r_pipe_ctor_args pipe_cfg;
    const struct rtpp_cfg *cfs = ap->cfs;
    struct common_cmd_args *ccap = ap->ccap;
    int i, lport = 0;
    struct rtpp_socket *fds[2];

    log = rtpp_log_ctor("rtpproxy", ccap->call_id->s, 0);
    if (log == NULL) {
        goto e0;
    }

    if (rtpp_create_listener(cfs, ap->lia[0], &lport, fds) == -1) {
        RTPP_LOG(log, RTPP_LOG_ERR, "can't create listener");
        goto e1;
    }

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_session_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e2;
    }

    pub = &(pvt->pub);
    pub->seuid = CALL_SMETHOD(cfs->guid, gen);

    CALL_METHOD(log, start, cfs);
    CALL_METHOD(log, setlevel, cfs->log_level);
    pipe_cfg = (struct r_pipe_ctor_args){.seuid = pub->seuid,
      .log = log, .pipe_type = PIPE_RTP, .session_cap = ap,
    };
    pub->rtp = rtpp_pipe_ctor(&pipe_cfg);
    if (pub->rtp == NULL) {
        goto e3;
    }
    /* spb is RTCP twin session for this one. */
    pipe_cfg.pipe_type = PIPE_RTCP;
    pub->rtcp = rtpp_pipe_ctor(&pipe_cfg);
    if (pub->rtcp == NULL) {
        goto e4;
    }
    pvt->acct = rtpp_acct_ctor(pub->seuid);
    if (pvt->acct == NULL) {
        goto e5;
    }
    pvt->acct->init_ts->wall = ap->dtime->wall;
    pvt->acct->init_ts->mono = ap->dtime->mono;

    if (rtpp_str_dup2(ccap->call_id, &pvt->call_id.ro) == NULL) {
        goto e6;
    }
    pub->call_id = &pvt->call_id.fx;
    if (rtpp_str_dup2(ccap->from_tag, &pvt->from_tag.ro) == NULL) {
        goto e7;
    }
    pub->from_tag = &pvt->from_tag.fx;
    rtpp_str_const_t tag_nomedianum = {.s = ccap->from_tag->s, .len = ccap->from_tag->len};
    const char *semi = memchr(tag_nomedianum.s, ';', tag_nomedianum.len);
    if (semi != NULL) {
        tag_nomedianum.len = semi - tag_nomedianum.s;
    }
    if (rtpp_str_dup2(&tag_nomedianum, &pvt->from_tag_nmn.ro) == NULL) {
        goto e8;
    }
    pub->from_tag_nmn = &pvt->from_tag_nmn.fx;
    if (ap->weak) {
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
                goto e9;
            }
        } else {
            pub->rtp->stream[i]->ttl = pub->rtp->stream[0]->ttl;
            RTPP_OBJ_INCREF(pub->rtp->stream[0]->ttl);
        }
        /* RTCP shares the same TTL */
        pub->rtcp->stream[i]->ttl = pub->rtp->stream[i]->ttl;
        RTPP_OBJ_INCREF(pub->rtp->stream[i]->ttl);
    }
    for (i = 0; i < 2; i++) {
        pub->rtp->stream[i]->stuid_rtcp = pub->rtcp->stream[i]->stuid;
        pub->rtcp->stream[i]->stuid_rtp = pub->rtp->stream[i]->stuid;
    }

    pvt->pub.rtpp_stats = cfs->rtpp_stats;
    pvt->pub.log = log;
    pvt->sessinfo = cfs->sessinfo;
    RTPP_OBJ_INCREF(cfs->sessinfo);
#if ENABLE_MODULE_IF
    if (cfs->modules_cf->count.sess_acct > 0) {
        RTPP_OBJ_INCREF(cfs->modules_cf);
        pvt->module_cf = cfs->modules_cf;
    }
#endif

    CALL_SMETHOD(cfs->sessinfo, append, pub, 0, fds);
    RTPP_OBJ_DECREF(fds[0]);
    RTPP_OBJ_DECREF(fds[1]);
    CALL_METHOD(cfs->rtpp_proc_cf, nudge);

    CALL_SMETHOD(pub->rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_session_dtor,
      pvt);
    return (&pvt->pub);

e9:
    free(pvt->from_tag_nmn.rw.s);
e8:
    free(pvt->from_tag.rw.s);
e7:
    free(pvt->call_id.rw.s);
e6:
    RTPP_OBJ_DECREF(pvt->acct);
e5:
    RTPP_OBJ_DECREF(pub->rtcp);
e4:
    RTPP_OBJ_DECREF(pub->rtp);
e3:
    RTPP_OBJ_DECREF(pub);
e2:
    RTPP_OBJ_DECREF(fds[0]);
    RTPP_OBJ_DECREF(fds[1]);
e1:
    RTPP_OBJ_DECREF(log);
e0:
    return (NULL);
}

static void
rtpp_session_dtor(struct rtpp_session_priv *pvt)
{
    int i;
    double session_time;
    struct rtpp_session *pub;

    pub = &(pvt->pub);
    rtpp_timestamp_get(pvt->acct->destroy_ts);
    session_time = pvt->acct->destroy_ts->mono - pvt->acct->init_ts->mono;

    CALL_SMETHOD(pub->rtp, get_stats, &pvt->acct->rtp);
    CALL_SMETHOD(pub->rtcp, get_stats, &pvt->acct->rtcp);
    if (pub->complete != 0) {
        CALL_SMETHOD(pub->rtp, upd_cntrs, &pvt->acct->rtp);
        CALL_SMETHOD(pub->rtcp, upd_cntrs, &pvt->acct->rtcp);
    }
    RTPP_LOG(pub->log, RTPP_LOG_INFO, "session on ports %d/%d is cleaned up",
      pub->rtp->stream[0]->port, pub->rtp->stream[1]->port);
    for (i = 0; i < 2; i++) {
        CALL_SMETHOD(pvt->sessinfo, remove, pub, i);
    }
    RTPP_OBJ_DECREF(pvt->sessinfo);
    CALL_SMETHOD(pub->rtpp_stats, updatebyname, "nsess_destroyed", 1);
    CALL_SMETHOD(pub->rtpp_stats, updatebyname_d, "total_duration",
      session_time);
    if (pvt->module_cf != NULL) {
        pvt->acct->call_id = pvt->call_id.rw.s;
        pvt->call_id.rw.s = NULL;
        pvt->acct->from_tag = pvt->from_tag.rw.s;
        pvt->from_tag.rw.s = NULL;
        CALL_SMETHOD(pub->rtp->stream[0]->analyzer, get_stats, \
          pvt->acct->rasto);
        CALL_SMETHOD(pub->rtp->stream[1]->analyzer, get_stats, \
          pvt->acct->rasta);
        CALL_SMETHOD(pub->rtp->stream[0]->analyzer, get_jstats, \
          pvt->acct->jrasto);
        CALL_SMETHOD(pub->rtp->stream[1]->analyzer, get_jstats, \
          pvt->acct->jrasta);

        CALL_METHOD(pvt->module_cf, do_acct, pvt->acct);
        RTPP_OBJ_DECREF(pvt->module_cf);
    }
    RTPP_OBJ_DECREF(pvt->acct);

    RTPP_OBJ_DECREF(pvt->pub.log);
    if (pvt->pub.timeout_data != NULL)
        RTPP_OBJ_DECREF(pvt->pub.timeout_data);
    if (pvt->call_id.rw.s != NULL)
        free(pvt->call_id.rw.s);
    if (pvt->from_tag.rw.s != NULL)
        free(pvt->from_tag.rw.s);
    if (pvt->from_tag_nmn.rw.s != NULL)
        free(pvt->from_tag_nmn.rw.s);

    RTPP_OBJ_DECREF(pvt->pub.rtcp);
    RTPP_OBJ_DECREF(pvt->pub.rtp);
}

int
compare_session_tags(const rtpp_str_t *tag1, const rtpp_str_t *tag0,
  unsigned *medianum_p)
{

    if (tag1->len < tag0->len)
        return 0;
    if (!memcmp(tag1->s, tag0->s, tag0->len)) {
        if (tag1->len == tag0->len)
            return 1;
	if (tag1->s[tag0->len] == ';') {
	    if (medianum_p != NULL)
		*medianum_p = strtoul(tag1->s + tag0->len + 1, NULL, 10);
	    return 2;
	}
    }
    return 0;
}

struct session_match_args {
    const rtpp_str_t *from_tag;
    const rtpp_str_t *to_tag;
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

    if (rtpp_str_match(rsp->from_tag, map->from_tag)) {
        map->rval = 0;
        goto found;
    }
    if (map->to_tag != NULL) {
        switch (compare_session_tags(rsp->from_tag, map->to_tag, NULL)) {
        case 1:
            /* Exact tag match */
            map->rval = 1;
            goto found;

        case 2:
            /*
             * Reverse tag match without medianum. Medianum is always
             * applied to the from tag, verify that.
             */
            cp1 = strrchr(rsp->from_tag->s, ';');
            cp2 = strrchr(map->from_tag->s, ';');
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
    RTPP_OBJ_INCREF(rsp);
    RTPP_DBG_ASSERT(map->sp == NULL);
    map->sp = rsp;
    return (RTPP_HT_MATCH_BRK);
}

int
find_stream(const struct rtpp_cfg *cfsp, const rtpp_str_t *call_id,
  const rtpp_str_t *from_tag, const rtpp_str_t *to_tag, struct rtpp_session **spp)
{
    struct session_match_args ma;

    memset(&ma, '\0', sizeof(ma));
    ma.from_tag = from_tag;
    ma.to_tag = to_tag;
    ma.rval = -1;

    CALL_SMETHOD(cfsp->sessions_ht, foreach_key_str, call_id,
      rtpp_session_ematch, &ma);
    if (ma.rval != -1) {
        *spp = ma.sp;
    }
    return ma.rval;
}

struct rtpp_stream_pair
get_rtcp_pair(const struct rtpp_session *sessp, const struct rtpp_stream *rtp_strmp_in)
{

    for (int i = 0; i < 2; i++) {
        if (sessp->rtp->stream[i] != rtp_strmp_in)
            continue;
        return (struct rtpp_stream_pair){
           .in = sessp->rtcp->stream[i], .out = sessp->rtcp->stream[i ^ 1]
        };
    }
    return (struct rtpp_stream_pair){.ret = -1};
}
