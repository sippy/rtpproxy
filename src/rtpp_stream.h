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

struct rtpp_stream_obj;
struct rtpp_weakref_obj;
struct rtpp_stats_obj;
struct rtpp_log_obj;
struct rtpp_command;
struct rtp_packet;

DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_handle_play, int, char *,
  char *, int, struct rtpp_command *, int);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_handle_noplay, void);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_isplayer_active, int);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_finish_playback, void, uint64_t);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_get_actor, const char *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_get_proto, const char *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_latch, int, double,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_check_latch_override, int,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_fill_addr, void,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_guess_addr, int,
  struct rtp_packet *);
DEFINE_METHOD(rtpp_stream_obj, rtpp_stream_prefill_addr, void,
  struct sockaddr **, double);

enum rtpp_stream_side {RTPP_SSIDE_CALLER = 1, RTPP_SSIDE_CALLEE = 0};

struct rtpps_latch {
    int latched;
    unsigned int ssrc;
    int seq;
};

struct rtpp_stream_obj {
    /* ttl for stream */
    int ttl;
    /* Remote source address */
    struct sockaddr *addr;
    /* Save previous address when doing update */
    struct sockaddr *prev_addr;
    /* Flag which tells if we are allowed to update address with RTP src IP */
    struct rtpps_latch latch_info;
    /* Local listen address/port */
    struct sockaddr *laddr;
    int port;
    /* Descriptors */
    int fd;
    int asymmetric;
    /* Flags: strong create/delete; weak ones */
    int weak;
    /* Pointer to rtpp_record's opaque data type */
    void *rrc;
    /* References to fd-to-session table */
    int sidx;
    /* Flag that indicates whether or not address supplied by client can't be trusted */
    int untrusted_addr;
    struct rtp_resizer *resizer;
    struct rtpp_analyzer *analyzer;
    /* Timestamp of the last session update */
    double last_update;
    /* Supported codecs */
    char *codecs;
    /* Requested ptime */
    int ptime;
    /* Packets received */
    unsigned long npkts_in;
    /* Refcounter */
    struct rtpp_refcnt_obj *rcnt;
    /* UID, read-only */
    uint64_t stuid;
    /* Type of session we are associated with, read-only */
    int session_type;
    struct rtpp_log_obj *log;
    /* Public methods */
    rtpp_stream_handle_play_t handle_play;
    rtpp_stream_handle_noplay_t handle_noplay;
    rtpp_stream_isplayer_active_t isplayer_active;
    rtpp_stream_finish_playback_t finish_playback;
    rtpp_stream_get_actor_t get_actor;
    rtpp_stream_get_proto_t get_proto;
    rtpp_stream_latch_t latch;
    rtpp_stream_check_latch_override_t check_latch_override;
    rtpp_stream_fill_addr_t fill_addr;
    rtpp_stream_guess_addr_t guess_addr;
    rtpp_stream_prefill_addr_t prefill_addr;
};

struct rtpp_stream_obj *rtpp_stream_ctor(struct rtpp_log_obj *,
  struct rtpp_weakref_obj *, struct rtpp_stats_obj *, enum rtpp_stream_side,
  int);

#endif
