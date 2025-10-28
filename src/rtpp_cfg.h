/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2019 Sippy Software, Inc., http://www.sippysoft.com
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

#pragma once

#if !defined(VERSION)
#error "config.h" needs to be included
#endif

/*
 * TTL counters are used to detect the absence of audio packets
 * in either direction.  When the counter reaches 0, the call timeout
 * occurs.
 */
enum rtpp_ttl_mode {
    TTL_UNIFIED = 0,            /* all TTL counters must reach 0 */
    TTL_INDEPENDENT = 1         /* any TTL counter reaches 0 */
};

typedef enum rtpp_ttl_mode rtpp_ttl_mode;

struct rtpp_timed;
struct rtpp_sessinfo;
struct rtpp_log;
struct rtpp_runcreds;
struct rtpp_proc_ttl;
struct pproc_manager;
struct rtpp_locking;
struct rtpp_nofile;
struct rtpp_modman;

#define RTPP_PT_INET	0
#define	RTPP_PT_INET6	1
#define	RTPP_PT_MAX	RTPP_PT_INET6
#define	RTPP_PT_LEN	(RTPP_PT_MAX + 1)
#define	RTPP_PT_SELECT(cp, af) (((af) == AF_INET) ? \
  (cp)->port_table[RTPP_PT_INET] : (cp)->port_table[RTPP_PT_INET6])

struct overload_prot {
    double low_trs;
    double high_trs;
    int ecode;
};

struct rtpp_run_options {
    int no_daemon;
    int no_chdir;
    int no_pid;
    int no_sigtrap;
};

struct rtpp_cfg {
    const char *pid_file;

    struct rtpp_run_options ropts;
    int dmode;
    int bmode;                  /* Bridge mode */
    int aforce;			/* Force asymmertic mode for all calls */
    int port_min;               /* Lowest UDP port for RTP */
    int port_max;               /* Highest UDP port number for RTP */
    int seq_ports;              /* Allocate ports in sequential manner rather than randomly */
    int port_ctl;               /* Port number for UDP control, 0 for Unix domain */
    int max_ttl;
    int max_setup_ttl;
    /*
     * The first address is for external interface, the second one - for
     * internal one. Second can be NULL, in this case there is no bridge
     * mode enabled.
     */
    const struct sockaddr *bindaddr[2];   /* RTP socket(s) addresses */
    char const * advaddr[2];        /* advertised addresses */
    int tos;

    const char *rdir;
    const char *sdir;
    int record_pcap;                /* Record in the PCAP format? */
    int record_all;                 /* Record everything */

    int rrtcp;                      /* Whether or not to relay RTCP? */
    struct rtpp_log *glog;

    struct rtpp_nofile *nofile;
    int no_check;

    rtpp_ttl_mode ttl_mode;

    struct rtpp_runcreds *runcreds;

    int log_level;
    int log_facility;

    struct rtpp_port_table *port_table[RTPP_PT_LEN];

    struct rtpp_hash_table *sessions_ht;
    struct rtpp_weakref *sessions_wrt;
    struct rtpp_weakref *rtp_streams_wrt;
    struct rtpp_weakref *rtcp_streams_wrt;

    int sched_policy;
    int sched_hz;
    int sched_nice;
    double target_pfreq;
    struct rtpp_cmd_async *rtpp_cmd_cf;
    struct rtpp_proc_async *rtpp_proc_cf;
    struct rtpp_proc_ttl *rtpp_proc_ttl_cf;
    struct rtpp_tnotify_set *rtpp_tnset_cf;
    struct rtpp_notify *rtpp_notify_cf;
    struct rtpp_bindaddrs *bindaddrs_cf;
    int slowshutdown;
    int fastshutdown;

    struct rtpp_stats *rtpp_stats;
    struct rtpp_list *ctrl_socks;
    struct rtpp_timed *rtpp_timed_cf;
    struct rtpp_sessinfo *sessinfo;
    const char *cwd_orig;

    struct overload_prot overload_prot;

    const char *cfile;

    struct pproc_manager *pproc_manager;

    struct rtpp_locking *locks;

    int no_resolve;
    int no_redirect;

    struct rtpp_proc_servers *proc_servers;
    struct rtpp_genuid *guid;

    int is_lib;
#if ENABLE_MODULE_IF
    struct rtpp_modman *modules_cf;
#else
    void *_pad;
#endif
};
