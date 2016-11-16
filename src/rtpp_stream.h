/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_STREAM_H_
#define _RTPP_STREAM_H_

struct rtpp_stream;
struct rtpp_weakref_obj;
struct rtpp_stats;
struct rtpp_log;
struct rtpp_command;
struct rtp_packet;
struct sockaddr;
struct rtpp_socket;
struct rtpp_record;
struct rtpp_ttl;
struct rtpp_pcount;
struct rtpp_netaddr;
struct sthread_args;
struct rtpp_acct_hold;

DEFINE_METHOD(rtpp_stream, rtpp_stream_handle_play, int, char *,
  char *, int, struct rtpp_command *, int);
DEFINE_METHOD(rtpp_stream, rtpp_stream_handle_noplay, void);
DEFINE_METHOD(rtpp_stream, rtpp_stream_isplayer_active, int);
DEFINE_METHOD(rtpp_stream, rtpp_stream_finish_playback, void, uint64_t);
DEFINE_METHOD(rtpp_stream, rtpp_stream_get_actor, const char *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_get_proto, const char *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_latch, int, double,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_check_latch_override, int,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_fill_addr, void,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_guess_addr, int,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_prefill_addr, void,
  struct sockaddr **, double);
DEFINE_METHOD(rtpp_stream, rtpp_stream_get_rtps, uint64_t);
DEFINE_METHOD(rtpp_stream, rtpp_stream_replace_rtps, void, uint64_t,
  uint64_t);
DEFINE_METHOD(rtpp_stream, rtpp_stream_send_pkt, int, struct sthread_args *,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream, rtpp_stream_islatched, int);
DEFINE_METHOD(rtpp_stream, rtpp_stream_locklatch, void);
DEFINE_METHOD(rtpp_stream, rtpp_stream_reg_onhold, void);
DEFINE_METHOD(rtpp_stream, rtpp_stream_get_stats, void,
  struct rtpp_acct_hold *);

enum rtpp_stream_side {RTPP_SSIDE_CALLER = 1, RTPP_SSIDE_CALLEE = 0};

struct rtpp_stream_smethods {
    /* Static methods */
    METHOD_ENTRY(rtpp_stream_handle_play, handle_play);
    METHOD_ENTRY(rtpp_stream_handle_noplay, handle_noplay);
    METHOD_ENTRY(rtpp_stream_isplayer_active, isplayer_active);
    METHOD_ENTRY(rtpp_stream_finish_playback, finish_playback);
    METHOD_ENTRY(rtpp_stream_get_actor, get_actor);
    METHOD_ENTRY(rtpp_stream_get_proto, get_proto);
    METHOD_ENTRY(rtpp_stream_latch, latch);
    METHOD_ENTRY(rtpp_stream_check_latch_override, check_latch_override);
    METHOD_ENTRY(rtpp_stream_fill_addr, fill_addr);
    METHOD_ENTRY(rtpp_stream_guess_addr, guess_addr);
    METHOD_ENTRY(rtpp_stream_prefill_addr, prefill_addr);
    METHOD_ENTRY(rtpp_stream_get_rtps, get_rtps);
    METHOD_ENTRY(rtpp_stream_replace_rtps, replace_rtps);
    METHOD_ENTRY(rtpp_stream_send_pkt, send_pkt);
    METHOD_ENTRY(rtpp_stream_islatched, islatched);
    METHOD_ENTRY(rtpp_stream_locklatch, locklatch);
    METHOD_ENTRY(rtpp_stream_reg_onhold, reg_onhold);
    METHOD_ENTRY(rtpp_stream_get_stats, get_stats);
};

struct rtpp_stream {
    /* ttl for stream */
    struct rtpp_ttl *ttl;
    /* Remote source address */
    struct rtpp_netaddr *rem_addr;
    /* Local listen address/port */
    struct sockaddr *laddr;
    int port;
    /* Descriptors */
    struct rtpp_socket *fd;
    int asymmetric;
    /* Flags: strong create/delete; weak ones */
    int weak;
    /* Pointer to rtpp_record's opaque data type */
    struct rtpp_record *rrc;
    struct rtp_resizer *resizer;
    struct rtpp_analyzer *analyzer;
    /* Supported codecs */
    char *codecs;
    /* Requested ptime */
    int ptime;
    /* Refcounter */
    struct rtpp_refcnt *rcnt;
    /* UID, read-only */
    uint64_t stuid;
    /* UID of the session we belong to, read-only */
    uint64_t seuid;
    /* UID of the associated "sending" stream, read-only */
    uint64_t stuid_sendr;
    /* UID of the associated "RTCP" stream, read-only */
    uint64_t stuid_rtcp;
    /* UID of the associated "RTP" stream, read-only */
    uint64_t stuid_rtp;
    /* Type of pipe we are associated with, read-only */
    int pipe_type;
    struct rtpp_log *log;
    /* Copy of the per-pipe counters */
    struct rtpp_pcount *pcount;
    /* Per-stream counters */
    struct rtpp_pcnt_strm *pcnt_strm;
    /* Public methods */
    const struct rtpp_stream_smethods *smethods;
};

struct rtpp_stream *rtpp_stream_ctor(struct rtpp_log *,
  struct rtpp_weakref_obj *, struct rtpp_stats *, enum rtpp_stream_side,
  int, uint64_t);
void rtpp_stream_latch_sync(struct rtpp_stream *, double,
  struct rtp_packet *);

#endif
