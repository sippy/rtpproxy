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

#ifndef _RTPP_DEFINES_H_
#define _RTPP_DEFINES_H_

/*
 * Version of the command protocol, bump only when backward-incompatible
 * change is introduced
 */
#define	CPROTOVER	20040107

#define	PORT_MIN	35000
#define	PORT_MAX	65000
#define	TIMETICK	1	/* in seconds */
#define	SESSION_TIMEOUT	60	/* in ticks */
#define	TOS		0xb8
#define	LBR_THRS	128	/* low-bitrate threshold */
#define	CPORT		"22222"
#define	MAX_RTP_RATE	100
#define	POLL_RATE	(MAX_RTP_RATE * 2)	/* target number of poll(2) calls per second */
#define	LOG_LEVEL	RTPP_LOG_DBUG
#define	UPDATE_WINDOW	10.0	/* in seconds */
#define	PCAP_FORMAT	DLT_EN10MB

/* Dummy service, getaddrinfo needs it */
#define	SERVICE		"34999"

#define	CMD_SOCK	"/var/run/rtpproxy.sock"
#define	PID_FILE	"/var/run/rtpproxy.pid"

#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

struct pollfd;
struct bindaddr_list;
struct rtpp_timeout_handler;

struct rtpp_hash_table;
struct rtpp_cfg_stable;

struct cfg {
    struct rtpp_cfg_stable *stable;

    /*
     * Data fields that must be locked separately from the main configuration
     * structure below.
     */

    struct bindaddr_list *bindaddr_list;
    pthread_mutex_t bindaddr_lock;

    int nofile_limit_warned;

    pthread_mutex_t glock;
};

#endif
