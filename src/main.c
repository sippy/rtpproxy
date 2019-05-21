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

#ifdef LINUX_XXX
/* Apparently needed for drand48(3) */
#define _SVID_SOURCE	1
/* Needed for the asprintf(3) */
#define _GNU_SOURCE	1
#endif

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

#ifdef HAVE_SYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif

#include <elperiodic.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_runcreds.h"
#include "rtpp_cfile.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_command.h"
#include "rtpp_controlfd.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_hash_table.h"
#include "rtpp_command_ver.h"
#include "rtpp_command_async.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_port_table.h"
#include "rtpp_proc_async.h"
#include "rtpp_bindaddrs.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_math.h"
#include "rtpp_mallocs.h"
#if ENABLE_MODULE_IF
#include "rtpp_module_if.h"
#endif
#include "rtpp_stats.h"
#include "rtpp_sessinfo.h"
#include "rtpp_list.h"
#include "rtpp_time.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_tnotify_set.h"
#include "rtpp_weakref.h"
#include "rtpp_debug.h"
#ifdef RTPP_CHECK_LEAKS
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"
#endif
#if RTPP_DEBUG_catchtrace
#include "rtpp_stacktrace.h"
#endif

#ifndef RTPP_DEBUG
# define RTPP_DEBUG	0
#else
# define RTPP_DEBUG	1
#endif

#define PRIO_UNSET (PRIO_MIN - 1)

static void usage(void);

#ifdef RTPP_CHECK_LEAKS
RTPP_MEMDEB_APP_STATIC;
#endif

static void
usage(void)
{

    fprintf(stderr, "usage:\trtpproxy [-2fvFiPaRbD] [-l addr1[/addr2]] "
      "[-6 addr1[/addr2]] [-s path]\n\t  [-t tos] [-r rdir [-S sdir]] [-T ttl] "
      "[-L nfiles] [-m port_min]\n\t  [-M port_max] [-u uname[:gname]] [-w sock_mode] "
      "[-n timeout_socket]\n\t  [-d log_level[:log_facility]] [-p pid_file]\n"
      "\t  [-c fifo|rr] [-A addr1[/addr2] [-N random/sched_offset] [-W setup_ttl]\n"
      "\trtpproxy -V\n");
    exit(1);
}

static struct cfg *_sig_cf;

static void rtpp_exit(int, int) __attribute__ ((noreturn));

static void
rtpp_exit(int memdeb, int rval)
{
    int ecode;

    ecode = 0;
#ifdef RTPP_CHECK_LEAKS
    if (memdeb) {
        ecode = rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) == 0 ? 0 : 1;
    }
#endif
    exit(rval == 0 ? ecode : rval);
}

static void
rtpp_glog_fin(void)
{

    CALL_SMETHOD(_sig_cf->stable->glog->rcnt, decref);
#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_FIN(rtpproxy);
#ifdef RTPP_MEMDEB_STDOUT
    fclose(stdout);
#endif
#endif
}

static void
fatsignal(int sig)
{

    RTPP_LOG(_sig_cf->stable->glog, RTPP_LOG_INFO, "got signal %d", sig);
    if (_sig_cf->stable->fastshutdown == 0) {
        _sig_cf->stable->fastshutdown = 1;
        return;
    }
    /*
     * Got second signal while already in the fastshutdown mode, something
     * probably jammed, do quick exit right from sighandler.
     */
    rtpp_exit(1, 0);
}

static void
sighup(int sig)
{

    if (_sig_cf->stable->slowshutdown == 0) {
        RTPP_LOG(_sig_cf->stable->glog, RTPP_LOG_INFO,
          "got SIGHUP, initiating deorbiting-burn sequence");
    }
    _sig_cf->stable->slowshutdown = 1;
}

static void
ehandler(void)
{

#if RTPP_DEBUG_catchtrace 
    rtpp_stacktrace_print("Exiting from: ehandler()");
#endif
    rtpp_controlfd_cleanup(_sig_cf);
    unlink(_sig_cf->stable->pid_file);
    RTPP_LOG(_sig_cf->stable->glog, RTPP_LOG_INFO, "rtpproxy ended");
}

long long
rtpp_rlim_max(struct cfg *cf)
{

    return (long long)(cf->stable->nofile_limit->rlim_max);
}

#define LOPT_DSO      256
#define LOPT_BRSYM    257
#define LOPT_NICE     258
#define LOPT_OVL_PROT 259
#define LOPT_CONFIG   260

const static struct option longopts[] = {
    { "dso", required_argument, NULL, LOPT_DSO },
    { "bridge_symmetric", no_argument, NULL, LOPT_BRSYM },
    { "nice", required_argument, NULL, LOPT_NICE },
    { "overload_prot", optional_argument, NULL, LOPT_OVL_PROT },
    { "config", required_argument, NULL, LOPT_CONFIG },
    { NULL,  0,                 NULL, 0 }
};

static void
init_config_bail(struct rtpp_cfg_stable *cfsp, int rval, const char *msg, int memdeb)
{
    struct rtpp_module_if *mif, *tmp;
    struct rtpp_ctrl_sock *ctrl_sock;

    if (msg != NULL) {
        RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "%s", msg);
    }
    CALL_METHOD(cfsp->rtpp_tnset_cf, dtor);
    free(cfsp->nofile_limit);

    for (ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
      ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        free(ctrl_sock);
    }
    free(cfsp->ctrl_socks);
    free(cfsp->runcreds);
#if ENABLE_MODULE_IF
    for (mif = RTPP_LIST_HEAD(cfsp->modules_cf); mif != NULL; mif = tmp) {
        tmp = RTPP_ITER_NEXT(mif);
        CALL_SMETHOD(mif->rcnt, decref);
    }
#endif
    free(cfsp->modules_cf);
    rtpp_gen_uid_free();
    free(cfsp);
    rtpp_exit(memdeb, rval);
}

static void
init_config(struct cfg *cf, int argc, char **argv)
{
    int ch, i, umode, stdio_mode;
    char *bh[2], *bh6[2], *cp, *tp[2];
    const char *errmsg;
    struct passwd *pp;
    struct group *gp;
    double x, y;
    struct rtpp_ctrl_sock *ctrl_sock;
    int option_index, brsym;
    struct proto_cap *pcp;
    struct rtpp_module_if *mif;
    char mpath[PATH_MAX + 1];

    bh[0] = bh[1] = bh6[0] = bh6[1] = NULL;

    umode = stdio_mode = 0;

    cf->stable->pid_file = PID_FILE;

    cf->stable->port_min = PORT_MIN;
    cf->stable->port_max = PORT_MAX;
    cf->stable->port_ctl = 0;

    cf->stable->advaddr[0] = NULL;
    cf->stable->advaddr[1] = NULL;

    cf->stable->max_ttl = SESSION_TIMEOUT;
    cf->stable->tos = TOS;
    cf->stable->rrtcp = 1;
    cf->stable->runcreds->sock_mode = 0;
    cf->stable->ttl_mode = TTL_UNIFIED;
    cf->stable->log_level = -1;
    cf->stable->log_facility = -1;
    cf->stable->sched_offset = 0.0;
    cf->stable->sched_hz = rtpp_get_sched_hz();
    cf->stable->sched_policy = SCHED_OTHER;
    cf->stable->sched_nice = PRIO_UNSET;
    cf->stable->target_pfreq = MIN(POLL_RATE, cf->stable->sched_hz);
#if RTPP_DEBUG
    fprintf(stderr, "target_pfreq = %f\n", cf->stable->target_pfreq);
#endif
    cf->stable->slowshutdown = 0;
    cf->stable->fastshutdown = 0;

    cf->stable->rtpp_tnset_cf = rtpp_tnotify_set_ctor();
    if (cf->stable->rtpp_tnset_cf == NULL) {
        err(1, "rtpp_tnotify_set_ctor");
    }

    pthread_mutex_init(&cf->glock, NULL);
    pthread_mutex_init(&cf->bindaddr_lock, NULL);

    cf->stable->nofile_limit = malloc(sizeof(*cf->stable->nofile_limit));
    if (cf->stable->nofile_limit == NULL)
        err(1, "malloc");
    if (getrlimit(RLIMIT_NOFILE, cf->stable->nofile_limit) != 0)
	err(1, "getrlimit");

    option_index = -1;
    brsym = 0;
    while ((ch = getopt_long(argc, argv, "vf2Rl:6:s:S:t:r:p:T:L:m:M:u:Fin:Pad:"
      "VN:c:A:w:bW:DC", longopts, &option_index)) != -1) {
	switch (ch) {
        case LOPT_DSO:
            if (!RTPP_LIST_IS_EMPTY(cf->stable->modules_cf)) {
                 errx(1, "this version of the rtpproxy only supports loading a "
                   "single module");
            }
            cp = realpath(optarg, mpath);
            if (cp == NULL) {
                 err(1, "realpath");
            }
            mif = rtpp_module_if_ctor(cp);
            if (mif == NULL) {
                err(1, "%s: dymanic module constructor has failed", cp);
            }
            if (CALL_METHOD(mif, load, cf->stable, cf->stable->glog) != 0) {
                RTPP_LOG(cf->stable->glog, RTPP_LOG_ERR,
                  "%p: dymanic module load has failed", mif);
                exit(1);
            }
            rtpp_list_append(cf->stable->modules_cf, mif);
            break;

        case LOPT_BRSYM:
            brsym = 1;
            break;

        case LOPT_NICE:
            cf->stable->sched_nice = atoi(optarg);
            if (cf->stable->sched_nice > PRIO_MAX || cf->stable->sched_nice < PRIO_MIN) {
                errx(1, "%d: nice level is out of range %d..%d",
                  cf->stable->sched_nice, PRIO_MIN, PRIO_MAX);
            }
            break;

        case LOPT_OVL_PROT:
            cf->stable->overload_prot.low_trs = 0.85;
            cf->stable->overload_prot.high_trs = 0.90;
            cf->stable->overload_prot.ecode = ECODE_OVERLOAD;
            break;

        case LOPT_CONFIG:
            cf->stable->cfile = optarg;
            break;

        case 'c':
            if (strcmp(optarg, "fifo") == 0) {
                 cf->stable->sched_policy = SCHED_FIFO;
                 break;
            }
            if (strcmp(optarg, "rr") == 0) {
                 cf->stable->sched_policy = SCHED_RR;
                 break;
            }
            errx(1, "%s: unknown scheduling policy", optarg);
            break;

        case 'N':
	    if (strcmp(optarg, "random") == 0) {
                x = getdtime() * 1000000.0;
                srand48((long)x);
                cf->stable->sched_offset = drand48();
            } else {
                tp[0] = optarg;
                tp[1] = strchr(tp[0], '/');
       	        if (tp[1] == NULL) {
                    errx(1, "%s: -N should be in the format X/Y", optarg);
                }
                *tp[1] = '\0';
                tp[1]++;
                x = (double)strtol(tp[0], &tp[0], 10);
                y = (double)strtol(tp[1], &tp[1], 10);
                cf->stable->sched_offset = x / y;
            }
            x = (double)cf->stable->sched_hz / cf->stable->target_pfreq;
            cf->stable->sched_offset = trunc(x * cf->stable->sched_offset) / x;
            cf->stable->sched_offset /= cf->stable->target_pfreq;
            warnx("sched_offset = %f",  cf->stable->sched_offset);
            break;

	case 'f':
	    cf->stable->nodaemon = 1;
	    break;

	case 'l':
	    bh[0] = optarg;
	    bh[1] = strchr(bh[0], '/');
	    if (bh[1] != NULL) {
		*bh[1] = '\0';
		bh[1]++;
		cf->stable->bmode = 1;
		/*
		 * Historically, in bridge mode all clients are assumed to
		 * be asymmetric
		 */
		cf->stable->aforce = 1;
	    }
	    break;

	case '6':
	    bh6[0] = optarg;
	    bh6[1] = strchr(bh6[0], '/');
	    if (bh6[1] != NULL) {
		*bh6[1] = '\0';
		bh6[1]++;
		cf->stable->bmode = 1;
		cf->stable->aforce = 1;
	    }
	    break;

    case 'A':
        if (*optarg == '\0') {
            errx(1, "first advertised address is invalid");
        }
        cf->stable->advaddr[0] = optarg;
        cp = strchr(optarg, '/');
        if (cp != NULL) {
            *cp = '\0';
            cp++;
            if (*cp == '\0') {
                errx(1, "second advertised address is invalid");
            }
        }
        cf->stable->advaddr[1] = cp;
        break;

	case 's':
            ctrl_sock = rtpp_ctrl_sock_parse(optarg);
            if (ctrl_sock == NULL) {
                errx(1, "can't parse control socket argument");
            }
            rtpp_list_append(cf->stable->ctrl_socks, ctrl_sock);
            if (RTPP_CTRL_ISDG(ctrl_sock)) {
                umode = 1;
            } else if (ctrl_sock->type == RTPC_STDIO) {
                stdio_mode = 1;
            }
	    break;

	case 't':
	    cf->stable->tos = atoi(optarg);
	    if (cf->stable->tos > 255)
		errx(1, "%d: TOS is too large", cf->stable->tos);
	    break;

	case '2':
	    cf->stable->dmode = 1;
	    break;

	case 'v':
	    printf("Basic version: %d\n", CPROTOVER);
	    for (pcp = iterate_proto_caps(NULL); pcp != NULL; pcp = iterate_proto_caps(pcp)) {
		printf("Extension %s: %s\n", pcp->pc_id, pcp->pc_description);
	    }
	    init_config_bail(cf->stable, 0, NULL, 0);
	    break;

	case 'r':
	    cf->stable->rdir = optarg;
	    break;

	case 'S':
	    cf->stable->sdir = optarg;
	    break;

	case 'R':
	    cf->stable->rrtcp = 0;
	    break;

	case 'p':
	    cf->stable->pid_file = optarg;
	    break;

	case 'T':
	    cf->stable->max_ttl = atoi(optarg);
	    break;

	case 'L':
	    cf->stable->nofile_limit->rlim_cur = cf->stable->nofile_limit->rlim_max = atoi(optarg);
	    if (setrlimit(RLIMIT_NOFILE, cf->stable->nofile_limit) != 0)
		err(1, "setrlimit");
	    if (getrlimit(RLIMIT_NOFILE, cf->stable->nofile_limit) != 0)
		err(1, "getrlimit");
	    if (cf->stable->nofile_limit->rlim_max < atoi(optarg))
		warnx("limit allocated by setrlimit (%d) is less than "
		  "requested (%d)", (int) cf->stable->nofile_limit->rlim_max,
		  atoi(optarg));
	    break;

	case 'm':
	    cf->stable->port_min = atoi(optarg);
	    break;

	case 'M':
	    cf->stable->port_max = atoi(optarg);
	    break;

	case 'u':
	    cf->stable->runcreds->uname = optarg;
	    cp = strchr(optarg, ':');
	    if (cp != NULL) {
		if (cp == optarg)
		    cf->stable->runcreds->uname = NULL;
		cp[0] = '\0';
		cp++;
	    }
	    cf->stable->runcreds->gname = cp;
	    cf->stable->runcreds->uid = -1;
	    cf->stable->runcreds->gid = -1;
	    if (cf->stable->runcreds->uname != NULL) {
		pp = getpwnam(cf->stable->runcreds->uname);
		if (pp == NULL)
		    errx(1, "can't find ID for the user: %s", cf->stable->runcreds->uname);
		cf->stable->runcreds->uid = pp->pw_uid;
		if (cf->stable->runcreds->gname == NULL)
		    cf->stable->runcreds->gid = pp->pw_gid;
	    }
	    if (cf->stable->runcreds->gname != NULL) {
		gp = getgrnam(cf->stable->runcreds->gname);
		if (gp == NULL)
		    errx(1, "can't find ID for the group: %s", cf->stable->runcreds->gname);
		cf->stable->runcreds->gid = gp->gr_gid;
                if (cf->stable->runcreds->sock_mode == 0) {
                    cf->stable->runcreds->sock_mode = 0755;
                }
	    }
	    break;

	case 'w':
	    cf->stable->runcreds->sock_mode = atoi(optarg);
	    break;

	case 'F':
	    cf->stable->no_check = 1;
	    break;

	case 'i':
	    cf->stable->ttl_mode = TTL_INDEPENDENT;
	    break;

	case 'n':
	    if(strlen(optarg) == 0)
		errx(1, "timeout notification socket name too short");
            if (CALL_METHOD(cf->stable->rtpp_tnset_cf, append, optarg,
              &errmsg) != 0) {
                errx(1, "error adding timeout notification: %s", errmsg);
            }
	    break;

	case 'P':
	    cf->stable->record_pcap = 1;
	    break;

	case 'a':
	    cf->stable->record_all = 1;
	    break;

	case 'd':
	    cp = strchr(optarg, ':');
	    if (cp != NULL) {
		cf->stable->log_facility = rtpp_log_str2fac(cp + 1);
		if (cf->stable->log_facility == -1)
		    errx(1, "%s: invalid log facility", cp + 1);
		*cp = '\0';
	    }
	    cf->stable->log_level = rtpp_log_str2lvl(optarg);
	    if (cf->stable->log_level == -1)
		errx(1, "%s: invalid log level", optarg);
            CALL_METHOD(cf->stable->glog, setlevel, cf->stable->log_level);
	    break;

	case 'V':
	    printf("%s\n", RTPP_SW_VERSION);
	    init_config_bail(cf->stable, 0, NULL, 0);
	    break;

        case 'W':
            cf->stable->max_setup_ttl = atoi(optarg);
            break;

        case 'b':
            cf->stable->seq_ports = 1;
            break;

        case 'D':
	    cf->stable->no_chdir = 1;
	    break;

        case 'C':
	    printf("%s\n", get_mclock_name());
	    init_config_bail(cf->stable, 0, NULL, 0);
	    break;

	case '?':
	default:
	    usage();
	}
    }

    if (optind != argc) {
       warnx("%d extra unhandled argument%s at the end of the command line",
         argc - optind, (argc - optind) > 1 ? "s" : "");
       usage();
    }

    if (cf->stable->cfile != NULL) {
        if (rtpp_cfile_process(cf->stable) < 0) {
            init_config_bail(cf->stable, 1, "rtpp_cfile_process() failed", 1);
        }
    }

    if (cf->stable->bmode != 0 && brsym != 0) {
        cf->stable->aforce = 0;
    }

    if (cf->stable->max_setup_ttl == 0) {
        cf->stable->max_setup_ttl = cf->stable->max_ttl;
    }

    /* No control socket has been specified, add a default one */
    if (RTPP_LIST_IS_EMPTY(cf->stable->ctrl_socks)) {
        ctrl_sock = rtpp_ctrl_sock_parse(CMD_SOCK);
        if (ctrl_sock == NULL) {
            errx(1, "can't parse control socket: \"%s\"", CMD_SOCK);
        }
        rtpp_list_append(cf->stable->ctrl_socks, ctrl_sock);
    }

    if (cf->stable->rdir == NULL && cf->stable->sdir != NULL)
	errx(1, "-S switch requires -r switch");

    if (cf->stable->nodaemon == 0 && stdio_mode != 0)
        errx(1, "stdio command mode requires -f switch");

    if (cf->stable->no_check == 0 && getuid() == 0 && cf->stable->runcreds->uname == NULL) {
	if (umode != 0) {
	    errx(1, "running this program as superuser in a remote control "
	      "mode is strongly not recommended, as it poses serious security "
	      "threat to your system. Use -u option to run as an unprivileged "
	      "user or -F is you want to run as a superuser anyway.");
	} else {
	    warnx("WARNING!!! Running this program as superuser is strongly "
	      "not recommended, as it may pose serious security threat to "
	      "your system. Use -u option to run as an unprivileged user "
	      "or -F to surpress this warning.");
	}
    }

    /* make sure that port_min and port_max are even */
    if ((cf->stable->port_min % 2) != 0)
	cf->stable->port_min++;
    if ((cf->stable->port_max % 2) != 0) {
	cf->stable->port_max--;
    } else {
	/*
	 * If port_max is already even then there is no
	 * "room" for the RTCP port, go back by two ports.
	 */
	cf->stable->port_max -= 2;
    }

    if (!IS_VALID_PORT(cf->stable->port_min))
	errx(1, "invalid value of the port_min argument, "
	  "not in the range 1-65535");
    if (!IS_VALID_PORT(cf->stable->port_max))
	errx(1, "invalid value of the port_max argument, "
	  "not in the range 1-65535");
    if (cf->stable->port_min > cf->stable->port_max)
	errx(1, "port_min should be less than port_max");

    if (bh[0] == NULL && bh[1] == NULL && bh6[0] == NULL && bh6[1] == NULL) {
	bh[0] = "*";
    }

    for (i = 0; i < 2; i++) {
	if (bh[i] != NULL && *bh[i] == '\0')
	    bh[i] = NULL;
	if (bh6[i] != NULL && *bh6[i] == '\0')
	    bh6[i] = NULL;
    }

    i = ((bh[0] == NULL) ? 0 : 1) + ((bh[1] == NULL) ? 0 : 1) +
      ((bh6[0] == NULL) ? 0 : 1) + ((bh6[1] == NULL) ? 0 : 1);
    if (cf->stable->bmode != 0) {
	if (bh[0] != NULL && bh6[0] != NULL)
	    errx(1, "either IPv4 or IPv6 should be configured for external "
	      "interface in bridging mode, not both");
	if (bh[1] != NULL && bh6[1] != NULL)
	    errx(1, "either IPv4 or IPv6 should be configured for internal "
	      "interface in bridging mode, not both");
    if (cf->stable->advaddr[0] != NULL && cf->stable->advaddr[1] == NULL)
        errx(1, "two advertised addresses are required for internal "
          "and external interfaces in bridging mode");
	if (i != 2)
	    errx(1, "incomplete configuration of the bridging mode - exactly "
	      "2 listen addresses required, %d provided", i);
    } else if (i != 1) {
	errx(1, "exactly 1 listen addresses required, %d provided", i);
    }

    for (i = 0; i < 2; i++) {
	cf->stable->bindaddr[i] = NULL;
	if (bh[i] != NULL) {
	    cf->stable->bindaddr[i] = host2bindaddr(cf, bh[i], AF_INET, &errmsg);
	    if (cf->stable->bindaddr[i] == NULL)
		errx(1, "host2bindaddr: %s", errmsg);
	    continue;
	}
	if (bh6[i] != NULL) {
	    cf->stable->bindaddr[i] = host2bindaddr(cf, bh6[i], AF_INET6, &errmsg);
	    if (cf->stable->bindaddr[i] == NULL)
		errx(1, "host2bindaddr: %s", errmsg);
	    continue;
	}
    }
    if (cf->stable->bindaddr[0] == NULL) {
	cf->stable->bindaddr[0] = cf->stable->bindaddr[1];
	cf->stable->bindaddr[1] = NULL;
    }
}

static enum rtpp_timed_cb_rvals
update_derived_stats(double dtime, void *argp)
{
    struct rtpp_stats *rtpp_stats;

    rtpp_stats = (struct rtpp_stats *)argp;
    CALL_SMETHOD(rtpp_stats, update_derived, dtime);
    return (CB_MORE);
}

int
main(int argc, char **argv)
{
    int i, len;
    long long ncycles_ref, counter;
    struct cfg cf;
    char buf[256];
    struct sched_param sparam;
    void *elp;
    struct rtpp_timed_task *tp;
#if RTPP_DEBUG_timers
    double sleep_time, filter_lastval;
#endif
    struct rtpp_module_if *mif, *tmp;

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_APP_INIT();
#endif
    if (getdtime() == -1) {
        err(1, "timer self-test has failed: please check your build configuration");
        /* NOTREACHED */
    }

#ifdef RTPP_CHECK_LEAKS
    if (rtpp_memdeb_selftest(MEMDEB_SYM) != 0) {
        errx(1, "MEMDEB self-test has failed");
        /* NOTREACHED */
    }
    rtpp_memdeb_approve(MEMDEB_SYM, "addr2bindaddr", 100, "Too busy to fix now");
#endif

    memset(&cf, 0, sizeof(cf));

    cf.stable = rtpp_zmalloc(sizeof(struct rtpp_cfg_stable));
    if (cf.stable == NULL) {
         err(1, "can't allocate memory for the struct rtpp_cfg_stable");
         /* NOTREACHED */
    }
    cf.stable->ctrl_socks = rtpp_zmalloc(sizeof(struct rtpp_list));
    if (cf.stable->ctrl_socks == NULL) {
         err(1, "can't allocate memory for the struct ctrl_socks");
         /* NOTREACHED */
    }

    cf.stable->modules_cf = rtpp_zmalloc(sizeof(struct rtpp_list));
    if (cf.stable->modules_cf == NULL) {
         err(1, "can't allocate memory for the struct modules_cf");
         /* NOTREACHED */
    }

    cf.stable->runcreds = rtpp_zmalloc(sizeof(struct rtpp_runcreds));
    if (cf.stable->runcreds == NULL) {
         err(1, "can't allocate memory for the struct runcreds");
         /* NOTREACHED */
    }

    seedrandom();
    if (rtpp_gen_uid_init() != 0) {
        err(1, "rtpp_gen_uid_init() failed");
        /* NOTREACHED */
    }

    cf.stable->glog = rtpp_log_ctor("rtpproxy", NULL, LF_REOPEN);
    if (cf.stable->glog == NULL) {
        err(1, "can't initialize logging subsystem");
        /* NOTREACHED */
    }
 #ifdef RTPP_CHECK_LEAKS
    rtpp_memdeb_setlog(MEMDEB_SYM, cf.stable->glog);
 #endif

    _sig_cf = &cf;
    atexit(rtpp_glog_fin);

    init_config(&cf, argc, argv);

    cf.stable->sessions_ht = rtpp_hash_table_ctor(rtpp_ht_key_str_t, 0);
    if (cf.stable->sessions_ht == NULL) {
        err(1, "can't allocate memory for the hash table");
         /* NOTREACHED */
    }
    cf.stable->sessions_wrt = rtpp_weakref_ctor();
    if (cf.stable->sessions_wrt == NULL) {
        err(1, "can't allocate memory for the sessions weakref table");
         /* NOTREACHED */
    }
    cf.stable->rtp_streams_wrt = rtpp_weakref_ctor();
    if (cf.stable->rtp_streams_wrt == NULL) {
        err(1, "can't allocate memory for the RTP streams weakref table");
         /* NOTREACHED */
    }
    cf.stable->rtcp_streams_wrt = rtpp_weakref_ctor();
    if (cf.stable->rtcp_streams_wrt == NULL) {
        err(1, "can't allocate memory for the RTCP streams weakref table");
         /* NOTREACHED */
    }
    cf.stable->servers_wrt = rtpp_weakref_ctor();
    if (cf.stable->servers_wrt == NULL) {
        err(1, "can't allocate memory for the servers weakref table");
         /* NOTREACHED */
    }
    cf.stable->sessinfo = rtpp_sessinfo_ctor(cf.stable);
    if (cf.stable->sessinfo == NULL) {
        errx(1, "cannot construct rtpp_sessinfo structure");
    }

    cf.stable->rtpp_stats = rtpp_stats_ctor();
    if (cf.stable->rtpp_stats == NULL) {
        err(1, "can't allocate memory for the stats data");
         /* NOTREACHED */
    }

    for (i = 0; i <= RTPP_PT_MAX; i++) {
        cf.stable->port_table[i] = rtpp_port_table_ctor(cf.stable->port_min,
          cf.stable->port_max, cf.stable->seq_ports, cf.stable->port_ctl);
        if (cf.stable->port_table[i] == NULL) {
            err(1, "can't allocate memory for the ports data");
            /* NOTREACHED */
        }
    }

    if (rtpp_controlfd_init(&cf) != 0) {
        err(1, "can't initialize control socket%s",
          cf.stable->ctrl_socks->len > 1 ? "s" : "");
    }

    if (cf.stable->nodaemon == 0) {
        if (cf.stable->no_chdir == 0) {
            cf.stable->cwd_orig = getcwd(NULL, 0);
            if (cf.stable->cwd_orig == NULL) {
                err(1, "getcwd");
            }
        }
	if (rtpp_daemon(cf.stable->no_chdir, 0) == -1)
	    err(1, "can't switch into daemon mode");
	    /* NOTREACHED */
    }

    if (CALL_METHOD(cf.stable->glog, start, cf.stable) != 0) {
        /* We cannot possibly function with broken logs, bail out */
        syslog(LOG_CRIT, "rtpproxy pid %d has failed to initialize logging"
            " facilities: crash", getpid());
        err(1, "rtpproxy has failed to initialize logging facilities");
    }

    atexit(ehandler);
    RTPP_LOG(cf.stable->glog, RTPP_LOG_INFO, "rtpproxy started, pid %d", getpid());

#ifdef RTPP_CHECK_LEAKS
    rtpp_memdeb_setbaseln(MEMDEB_SYM);
#endif

    i = open(cf.stable->pid_file, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (i >= 0) {
	len = sprintf(buf, "%u\n", (unsigned int)getpid());
	write(i, buf, len);
	close(i);
    } else {
	RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR, "can't open pidfile for writing");
    }

    if (cf.stable->sched_policy != SCHED_OTHER) {
        sparam.sched_priority = sched_get_priority_max(cf.stable->sched_policy);
        if (sched_setscheduler(0, cf.stable->sched_policy, &sparam) == -1) {
            RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR, "sched_setscheduler(SCHED_%s, %d)",
              (cf.stable->sched_policy == SCHED_FIFO) ? "FIFO" : "RR", sparam.sched_priority);
        }
    }
    if (cf.stable->sched_nice != PRIO_UNSET) {
        if (setpriority(PRIO_PROCESS, 0, cf.stable->sched_nice) == -1) {
            RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR, "can't set scheduling "
              "priority to %d", cf.stable->sched_nice);
            exit(1);
        }
    }

    if (cf.stable->runcreds->uname != NULL || cf.stable->runcreds->gname != NULL) {
	if (drop_privileges(cf.stable) != 0) {
	    RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
	      "can't switch to requested user/group");
	    exit(1);
	}
    }
    set_rlimits(&cf);

    cf.stable->rtpp_proc_cf = rtpp_proc_async_ctor(&cf);
    if (cf.stable->rtpp_proc_cf == NULL) {
        RTPP_LOG(cf.stable->glog, RTPP_LOG_ERR,
          "can't init RTP processing subsystem");
        exit(1);
    }

    counter = 0;

    cf.stable->rtpp_timed_cf = rtpp_timed_ctor(0.1);
    if (cf.stable->rtpp_timed_cf == NULL) {
        RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
          "can't init scheduling subsystem");
        exit(1);
    }

    tp = CALL_SMETHOD(cf.stable->rtpp_timed_cf, schedule_rc, 1.0,
      cf.stable->rtpp_stats->rcnt, update_derived_stats, NULL,
      cf.stable->rtpp_stats);
    if (tp == NULL) {
        RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
          "can't schedule notification to derive stats");
        exit(1);
    }
    CALL_SMETHOD(tp->rcnt, decref);

    cf.stable->rtpp_notify_cf = rtpp_notify_ctor(cf.stable->glog);
    if (cf.stable->rtpp_notify_cf == NULL) {
        RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
          "can't init timeout notification subsystem");
        exit(1);
    }

#if ENABLE_MODULE_IF
    if (!RTPP_LIST_IS_EMPTY(cf.stable->modules_cf)) {
        mif = RTPP_LIST_HEAD(cf.stable->modules_cf);
        if (CALL_METHOD(mif, start) != 0) {
            RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
              "%p: dymanic module start has failed", mif);
            exit(1);
        }
    }
#endif

    cf.stable->rtpp_cmd_cf = rtpp_command_async_ctor(&cf);
    if (cf.stable->rtpp_cmd_cf == NULL) {
        RTPP_ELOG(cf.stable->glog, RTPP_LOG_ERR,
          "can't init command processing subsystem");
        exit(1);
    }

    signal(SIGHUP, sighup);
    signal(SIGINT, fatsignal);
    signal(SIGKILL, fatsignal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, fatsignal);
    signal(SIGXCPU, fatsignal);
    signal(SIGXFSZ, fatsignal);
    signal(SIGVTALRM, fatsignal);
    signal(SIGPROF, fatsignal);
    signal(SIGUSR1, fatsignal);
    signal(SIGUSR2, fatsignal);
#if RTPP_DEBUG_catchtrace
    signal(SIGQUIT, rtpp_stacktrace);
    signal(SIGILL, rtpp_stacktrace);
    signal(SIGTRAP, rtpp_stacktrace);
    signal(SIGABRT, rtpp_stacktrace);
#if defined(SIGEMT)
    signal(SIGEMT, rtpp_stacktrace);
#endif
    signal(SIGFPE, rtpp_stacktrace);
    signal(SIGBUS, rtpp_stacktrace);
    signal(SIGSEGV, rtpp_stacktrace);
    signal(SIGSYS, rtpp_stacktrace);
#endif

#ifdef HAVE_SYSTEMD_DAEMON
    sd_notify(0, "READY=1");
#endif

    elp = prdic_init(cf.stable->target_pfreq / 10.0, cf.stable->sched_offset);
    for (;;) {
        ncycles_ref = (long long)prdic_getncycles_ref(elp);

        CALL_METHOD(cf.stable->rtpp_cmd_cf, wakeup);
        if (cf.stable->fastshutdown != 0) {
            break;
        }
        if (cf.stable->slowshutdown != 0 &&
          CALL_METHOD(cf.stable->sessions_wrt, get_length) == 0) {
            RTPP_LOG(cf.stable->glog, RTPP_LOG_INFO,
              "deorbiting-burn sequence completed, exiting");
            break;
        }
        prdic_procrastinate(elp);
        counter++;
    }
    prdic_free(elp);

    CALL_METHOD(cf.stable->rtpp_cmd_cf, dtor);
#if ENABLE_MODULE_IF
    for (mif = RTPP_LIST_HEAD(cf.stable->modules_cf); mif != NULL; mif = tmp) {
        tmp = RTPP_ITER_NEXT(mif);
        CALL_SMETHOD(mif->rcnt, decref);
    }
#endif
    free(cf.stable->modules_cf);
    free(cf.stable->runcreds);
    CALL_METHOD(cf.stable->rtpp_notify_cf, dtor);
    CALL_METHOD(cf.stable->rtpp_tnset_cf, dtor);
    CALL_SMETHOD(cf.stable->rtpp_timed_cf, shutdown);
    CALL_SMETHOD(cf.stable->rtpp_timed_cf->rcnt, decref);
    CALL_METHOD(cf.stable->rtpp_proc_cf, dtor);
    CALL_SMETHOD(cf.stable->sessinfo->rcnt, decref);
    CALL_SMETHOD(cf.stable->rtpp_stats->rcnt, decref);
    for (i = 0; i <= RTPP_PT_MAX; i++) {
        CALL_SMETHOD(cf.stable->port_table[i]->rcnt, decref);
    }
#ifdef HAVE_SYSTEMD_DAEMON
    sd_notify(0, "STATUS=Exited");
#endif

    rtpp_exit(1, 0);
}
