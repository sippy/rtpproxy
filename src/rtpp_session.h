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

#ifndef _RTPP_SESSION_H_
#define _RTPP_SESSION_H_

struct rtpp_session_obj;

DEFINE_METHOD(rtpp_session_obj, rtpp_session_dtor, void);

struct rtpp_timeout_data {
    char *notify_tag;
    struct rtpp_tnotify_target *notify_target;
};

struct rtpp_hash_table_entry;

struct rtpps_pcount {
    unsigned long nrelayed;
    unsigned long ndropped;
    unsigned long nignored;
};

struct rtpp_session_obj {
    /* Session for caller [0] and callee [1] */
    struct rtpp_stream_obj *stream[2];
    rtpp_ttl_mode ttl_mode;
    struct rtpps_pcount pcount;
    char *call_id;
    char *tag;
    char *tag_nomedianum;
    rtpp_log_t log;
    struct rtpp_session_obj* rtcp;
    /* Session is complete, that is we received both request and reply */
    int complete;
    /* Flags: strong create/delete; weak ones */
    int strong;
    int record_single_file;
    struct rtpp_session_obj *prev;
    struct rtpp_session_obj *next;
    struct rtpp_timeout_data timeout_data;
    /* Timestamp of session instantiation time */
    double init_ts;
    struct rtpp_hash_table_entry *hte;
    /* UID */
    uint64_t seuid;
    /* Weakref to the main (RTP) */
    uint64_t rtp_seuid;

    struct rtpp_stats_obj *rtpp_stats;
    struct rtpp_weakref_obj *servers_wrt;

    /* Refcounter */
    struct rtpp_refcnt_obj *rcnt;
};

struct cfg;
struct cfg_stable;

#define	SESS_RTP	1
#define	SESS_RTCP	2

void init_hash_table(struct cfg_stable *);
struct rtpp_session_obj *session_findfirst(struct cfg *, const char *);
struct rtpp_session_obj *session_findnext(struct cfg *cf, struct rtpp_session_obj *);
void hash_table_append(struct cfg *, struct rtpp_session_obj *);
void append_session(struct cfg *, struct rtpp_session_obj *, int);
void update_sessions(struct cfg *, struct rtpp_session_obj *, int, int *);
void remove_session(struct cfg *, struct rtpp_session_obj *);
int compare_session_tags(const char *, const char *, unsigned *);
int find_stream(struct cfg *, const char *, const char *, const char *, struct rtpp_session_obj **);
int get_ttl(struct rtpp_session_obj *);

struct rtpp_session_obj *rtpp_session_ctor(struct rtpp_cfg_stable *, int);

#endif
