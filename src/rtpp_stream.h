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
    /* Weak reference to the "rtpp_server" (player) */
    uint64_t rtps;
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
    /* UID */
    uint64_t stuid;
};

struct rtpp_stream_obj *rtpp_stream_ctor(struct rtpp_weakref_obj *, struct rtpp_stats_obj *);

#endif
