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
 * $Id: rtpp_defines.h,v 1.8 2008/03/31 20:35:39 sobomax Exp $
 *
 */

#ifndef _RTPP_DEFINES_H_
#define _RTPP_DEFINES_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>

/*
 * Version of the command protocol, bump only when backward-incompatible
 * change is introduced
 */
#define	CPROTOVER	20040107

#define	PORT_MIN	35000
#define	PORT_MAX	65000
#define	TIMETICK	1.0	/* in seconds */
#define	SESSION_TIMEOUT	60	/* in ticks */
#define	TOS		0xb8
#define	LBR_THRS	128	/* low-bitrate threshold */
#define	CPORT		"22222"
#define	POLL_LIMIT	100	/* maximum number of poll(2) calls per second */
#define	LOG_LEVEL	RTPP_LOG_DBUG

/* Dummy service, getaddrinfo needs it */
#define	SERVICE		"34999"

#define	CMD_SOCK	"/var/run/rtpproxy.sock"
#define	PID_FILE	"/var/run/rtpproxy.pid"

#define	rtpp_log_t	int

struct cfg {
    int nodaemon;
    int dmode;
    int bmode;			/* Bridge mode */
    int umode;			/* UDP control mode */
    int port_min;		/* Lowest UDP port for RTP */
    int port_max;		/* Highest UDP port number for RTP */
    int nextport[2];
    struct rtpp_session **sessions;
    struct rtpp_session **rtp_servers;
    struct pollfd *pfds;
    int nsessions;
    int rtp_nsessions;
    unsigned long long sessions_created;
    int sessions_active;
    int max_ttl;
    /*
     * The first address is for external interface, the second one - for
     * internal one. Second can be NULL, in this case there is no bridge
     * mode enabled.
     */
    struct sockaddr *bindaddr[2];	/* RTP socket(s) addresses */
    int tos;
    const char *rdir;
    const char *sdir;
    int rrtcp;			/* Whether or not to relay RTCP? */
    rtpp_log_t glog;

    struct rlimit nofile_limit;
    int nofile_limit_warned;

    char *run_uname;
    char *run_gname;
    int no_check;
};

#endif
