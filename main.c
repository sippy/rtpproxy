/*
 * Copyright (c) 2003 Porta Software Ltd
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
 * $Id: main.c,v 1.2 2004/01/07 17:02:47 sobomax Exp $
 *
 * History:
 * --------
 * 2003-09-21: Added IPv4/IPv6 translation, Jan Janak <jan@iptel.org>
 * 2003-10-14: Added ability to alter location of the command socket
 * 2003-10-18: Added ability to set TOS (type of service) for rtp packets
 *	       Added "double RTP mode"
 * 2003-12-10: Added support for relaying RTCP
 * 2004-01-07: Major overhaul - now two ports are allocated for each session,
 *	       to make RTCP working properly, internal reorganisation,
 *	       new incompatible version of the command protocol, etc.
 *	       New command is added `V', which reports supported version of
 *	       of the command protocol.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#if defined(__FreeBSD__)
#include <sys/queue.h>
#else
#include "myqueue.h"
#endif
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#if !defined(__solaris__)
#include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#if !defined(INFTIM)
#define INFTIM (-1)
#endif

#if !defined(AF_LOCAL)
#define	AF_LOCAL AF_UNIX
#endif
#if !defined(PF_LOCAL)
#define	PF_LOCAL PF_UNIX
#endif

/*
 * Version of the command protocol, bump only when backward-incompatible
 * change is introduced
 */
#define	CPROTOVER	20040107

#define	PORT_MIN	35000
#define	PORT_MAX	65000
#define	MAX_FDS		((PORT_MAX - PORT_MIN + 1) * 2)
#define	TIMETICK	1	/* in seconds */
#define	SESSION_TIMEOUT	60	/* in ticks */
#define	TOS		0xb8
#define	LBR_THRS	128	/* low-bitrate threshold */

/* Dummy service, getaddrinfo needs it */
#define	SERVICE		"34999"

#define	CMD_SOCK	"/var/run/rtpproxy.sock"

#if defined(__solaris__)
#define err(exitcode, format, args...) \
  errx(exitcode, format ": %s", ## args, strerror(errno))
#define errx(exitcode, format, args...) \
  { warnx(format, ## args); exit(exitcode); }
#define warn(format, args...) \
  warnx(format ": %s", ## args, strerror(errno))
#define warnx(format, args...) \
  fprintf(stderr, format "\n", ## args)
#endif

#define	in_nullhost(x)	((x).s_addr == INADDR_ANY)

struct session {
    LIST_ENTRY(session) link;
    struct sockaddr *addr[4];
    int cleanup_in;
    unsigned long pcount[6];
    char *call_id;
    char *tag;
    struct session* rtcp;
    struct session* rtp;
    int fds[4];	/* Descriptors, first pair for IPv4, the second one for IPv6 */
    int ports[2];
};
static LIST_HEAD(, session) session_set = LIST_HEAD_INITIALIZER(&session_set);

static struct session *sessions[MAX_FDS];
static struct pollfd fds[MAX_FDS + 1];
static int nsessions;
static int use_ipv6;			/* IPv6 enabled/disabled */
static struct sockaddr_in bindaddr;	/* IPv4 socket address */
static struct sockaddr_in6 bindaddr6;	/* IPv6 socket address */
static int tos;
static int lastport = PORT_MIN - 1;

static void setbindhost(struct sockaddr *, int, const char *);
static void remove_session(struct session *);
static void rebuild_tables(void);
static void alarmhandler(int);
static int create_twinlistener(struct sockaddr *, int, int, int *);
static int create_listener(int, int, int, int *, int *);
static void handle_command(int);
static void usage(void);

static void
setbindhost(struct sockaddr *ia, int pf, const char *bindhost)
{
    int n;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;	/* We create listening sockets */
    hints.ai_family = pf;		/* Protocol family */
    hints.ai_socktype = SOCK_DGRAM;	/* UDP */

    /*
     * If user specified * then change it to NULL,
     * that will make getaddrinfo to return addr_any socket
     */
    if (bindhost && (strcmp(bindhost, "*") == 0))
	bindhost = NULL;

    if ((n = getaddrinfo(bindhost, SERVICE, &hints, &res)) != 0)
	errx(1, "setbindhost: %s", gai_strerror(n));

    /* Use the first socket address returned */
    memcpy(ia, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
}

static void
rebuild_tables(void)
{
    struct session *sp;
    int i, j;

    i = 0;
    LIST_FOREACH(sp, &session_set, link) {
	for (j = 0; j < 4; j++) {
	    if (sp->fds[j] == -1)
		continue;
	    fds[i + 1].fd = sp->fds[j];
	    fds[i + 1].events = POLLIN;
	    fds[i + 1].revents = 0;
	    sessions[i] = sp;
	    i++;
	}
    }
    nsessions = i;
}

static void
alarmhandler(int sig)
{
    struct session *sp, *rsp;
    int changed;

    changed = 0;
    for(sp = LIST_FIRST(&session_set); sp != NULL; sp = rsp) {
	rsp = LIST_NEXT(sp, link);
	if (sp->rtcp == NULL)
	    continue;
	if (sp->cleanup_in == 0) {
	    warnx("session timeout");
	    remove_session(sp);
	    changed = 1;
	    continue;
	}
	sp->cleanup_in--;
    }
    if (changed == 1)
	rebuild_tables();
}

static void
remove_session(struct session *sp)
{
    int i;

    warnx(
      "RTP stats: %lu in from callee, %lu in from caller, %lu relayed, "
      "%lu dropped",
      (sp->pcount[0] > 0) ? sp->pcount[0] : sp->pcount[2],
      (sp->pcount[1] > 0) ? sp->pcount[1] : sp->pcount[3],
      sp->pcount[4], sp->pcount[5]);
    warnx(
      "RTCP stats: %lu in from callee, %lu in from caller, %lu relayed, "
      "%lu dropped",
      (sp->rtcp->pcount[0] > 0) ? sp->rtcp->pcount[0] : sp->rtcp->pcount[2],
      (sp->rtcp->pcount[1] > 0) ? sp->rtcp->pcount[1] : sp->rtcp->pcount[3],
      sp->rtcp->pcount[4], sp->rtcp->pcount[5]);
    warnx("session on ports %d/%d is cleaned up",
      sp->ports[0], sp->ports[1]);
    for (i = 0; i < 4; i++) {
	if (sp->fds[i] != -1)
	    close(sp->fds[i]);
	if (sp->rtcp->fds[i] != -1)
	    close(sp->rtcp->fds[i]);
	if (sp->addr[i] != NULL)
	    free(sp->addr[i]);
	if (sp->rtcp->addr[i] != NULL)
	    free(sp->rtcp->addr[i]);
    }
    if (sp->call_id != NULL)
	free(sp->call_id);
    if (sp->tag != NULL)
	free(sp->tag);
    LIST_REMOVE(sp, link);
    LIST_REMOVE(sp->rtcp, link);
    free(sp->rtcp);
    free(sp);
}

static int
create_twinlistener(struct sockaddr *ia, int pf, int port, int *fds)
{
    struct sockaddr iac;
    int rval, i, size;

    fds[0] = fds[1] = -1;

    rval = -1;
    size = (pf == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    for (i = 0; i < 2; i++) {
	fds[i] = socket(pf, SOCK_DGRAM, 0);
	if (fds[i] == -1) {
	    warn("can't create %s socket",
	      (pf == AF_INET) ? "IPv4" : "IPv6");
	    goto failure;
	}
	memcpy(&iac, ia, size);
	((struct sockaddr_in *)&iac)->sin_port = htons(port);
	if (bind(fds[i], (struct sockaddr *)&iac, size) != 0) {
	    if (errno != EADDRINUSE && errno != EACCES) {
		warn("can't bind to the %s port %d",
		  (pf == AF_INET) ? "IPv4" : "IPv6", port);
	    } else {
		rval = -2;
	    }
	    goto failure;
	}
	port++;
	if (setsockopt(fds[i], IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1)
	    warn("unable to set TOS to %d", tos);
    }
    return 0;

failure:
    for (i = 0; i < 2; i++)
	if (fds[i] != -1) {
	    close(fds[i]);
	    fds[i] = -1;
	}
    return rval;
}

static int
create_listener(int minport, int maxport, int startport, int *port, int *fds)
{
    int init, rval;

    /* make sure that {min,max,start}port is even */
    if ((minport & 0x1) != 0)
	minport++;
    if ((maxport & 0x1) != 0)
	maxport--;
    if ((startport & 0x1) != 0)
	startport++;

    init = 0;
    if (startport < minport || startport > maxport)
	startport = minport;
    for (*port = startport; *port != startport || init == 0; (*port) += 2) {
	init = 1;
	rval = create_twinlistener((struct sockaddr *)&bindaddr, AF_INET,
	    *port, fds);
	if (rval != 0) {
	    if (rval == -1)
		break;
	    if (*port >= maxport)
		*port = minport - 2;
	    continue;
	}

	if (use_ipv6) {
	    rval = create_twinlistener((struct sockaddr *)&bindaddr6, AF_INET6,
		*port, fds + 2);
	    if (rval != 0) {
		close(fds[0]);
		close(fds[1]);
		if (rval == -1)
		    break;
		if (*port >= maxport)
		    *port = minport - 2;
		continue;
	    }
	}
	return 0;
    }
    return -1;
}

static void
handle_command(int controlfd)
{
    int len, update, delete, argc, i, pidx;
    int fds[8], ports[2];
    char buf[1024 * 8];
    char *cp, *call_id, *from_tag, *to_tag, *addr, *port;
    struct session *spa, *spb;
    char **ap, *argv[10];
    struct sockaddr *ia[2];
    struct addrinfo hints, *res;

    (void *)ia[0] = (void *)ia[1] = (void *)res = spa = spb = NULL;
    for (i = 0; i < 8; i++)
	fds[i] = -1;

    do {
	len = read(controlfd, buf, sizeof(buf) - 1);
    } while (len == -1 && errno == EINTR);
    if (len == -1)
	warn("can't read from control socket");
    buf[len] = '\0';

    cp = buf;
    argc = 0;
    memset(argv, 0, sizeof(argv));
    for (ap = argv; (*ap = strsep(&cp, "\r\n\t ")) != NULL;)
	if (**ap != '\0') {
	    argc++;
	    if (++ap >= &argv[10])
		break;
	}
    if (argc < 1) {
	warnx("command syntax error");
	return;
    }

    delete = 0;
    update = 0;
    addr = port = NULL;
    switch (argv[0][0]) {
    case 'u':
    case 'U':
	if (argc < 5 || argc > 6) {
	    warnx("command syntax error");
	    return;
	}
	update = 1;
	addr = argv[2];
	port = argv[3];
	from_tag = argv[4];
	to_tag = argv[5];
	break;

    case 'l':
    case 'L':
	if (argc < 5 || argc > 6) {
	    warnx("command syntax error");
	    return;
	}
	update = 0;
	addr = argv[2];
	port = argv[3];
	from_tag = argv[4];
	to_tag = argv[5];
	break;

    case 'd':
    case 'D':
	if (argc < 3 || argc > 4) {
	    warnx("command syntax error");
	    return;
	}
	delete = 1;
	from_tag = argv[2];
	to_tag = argv[3];
	break;

    case 'v':
    case 'V':
	if (argc > 1) {
	    warnx("command syntax error");
	    return;
	}
	len = sprintf(buf, "%d\n", CPROTOVER);
	goto doreply;
	break;

    default:
	warnx("unknown command");
	return;
    }
    call_id = argv[1];

    if (delete == 0 && addr != NULL && port != NULL && strlen(addr) >= 7) {
	int n;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;/* Address is numeric */
	hints.ai_family = AF_INET;	/* Protocol family, so far IPv4 only */
	hints.ai_socktype = SOCK_DGRAM;	/* UDP */

	if ((n = getaddrinfo(addr, port, &hints, &res)) == 0) {
	    if (!in_nullhost(((struct sockaddr_in *)res->ai_addr)->sin_addr)) {
		for (i = 0; i < 2; i++) {
		    ia[i] = malloc(res->ai_addrlen);
		    if (ia[i] == NULL)
			goto nomem;
		    /* Use the first socket address returned */
		    memcpy(ia[i], res->ai_addr, res->ai_addrlen);
		}
		/* Set port for RTCP, will work both for IPv4 and IPv6 */
		n = ntohs(((struct sockaddr_in *)ia[1])->sin_port);
		((struct sockaddr_in *)ia[1])->sin_port = htons(n + 1);
	    }
	} else {
	    warnx("getaddrinfo: %s", gai_strerror(n));
	}
	freeaddrinfo(res);
	res = NULL;
    }

    ports[0] = ports[1] = 0;
    pidx = 1;
    LIST_FOREACH(spa, &session_set, link) {
	if (spa->rtcp == NULL || spa->call_id == NULL ||
	  strcmp(spa->call_id, call_id) != 0)
	    continue;
	if (strcmp(spa->tag, from_tag) == 0)
	    i = (update == 0) ? 1 : 0;
	else if (to_tag != NULL && strcmp(spa->tag, to_tag) == 0)
	    i = (update == 0) ? 0 : 1;
	else
	    continue;
	if (delete == 1) {
	    warnx(
	      "forcefully deleting session on ports %d/%d", spa->ports[0],
	      spa->ports[1]);
	    remove_session(spa);
	    rebuild_tables();
	    return;
	}
	ports[0] = spa->ports[i];
	pidx = (i == 0) ? 1 : 0;
	spa->cleanup_in = SESSION_TIMEOUT;
	warnx(
	  "lookup on a ports %d/%d, session timer restarted", spa->ports[0],
	  spa->ports[1]);
	goto writeport;
    }
    if (delete == 1) {
	warnx(
	  "delete request failed: session %s, tags %s/%s not found", call_id,
	  from_tag, to_tag != NULL ? to_tag : "NONE");
	return;
    }

    if (update == 0) {
	warnx(
	  "lookup request: session %s, tags %s/%s not found", call_id,
	  from_tag, to_tag != NULL ? to_tag : "NONE");
	pidx = -1;
	goto writeport;
    }

    warnx("new session %s, tag %s requested", call_id,
      from_tag);

    for (i = 0; i < 2; i++) {
	if (create_listener(PORT_MIN, PORT_MAX, lastport, &ports[i],
	  fds + i * 4) == -1) {
	    warnx("can't create listener");
	    if (i == 1)
		for (i = 0; i < 4; i++)
		    fds[i + 4] = -1;
	    goto freeall;
	}
	lastport = ports[i];
    }

    spa = malloc(sizeof(*spa));
    if (spa == NULL)
	goto nomem;
    spb = malloc(sizeof(*spb));
    if (spb == NULL)
	goto nomem;
    memset(spa, 0, sizeof(*spa));
    memset(spb, 0, sizeof(*spb));
    for (i = 0; i < 4; i++)
	spa->fds[i] = spb->fds[i] = -1;
    spa->call_id = strdup(call_id);
    if (spa->call_id == NULL)
	goto nomem;
    spb->call_id = spa->call_id;
    spa->tag = strdup(from_tag);
    if (spa->tag == NULL)
	goto nomem;
    spb->tag = spa->tag;
    for (i = 0; i < 2; i++) {
	spa->fds[i] = fds[0 + i * 4];
	spb->fds[i] = fds[1 + i * 4];
	spa->fds[2 + i] = (use_ipv6) ? fds[2 + i * 4] : -1;
	spb->fds[2 + i] = (use_ipv6) ? fds[3 + i * 4] : -1;
	spa->ports[i] = ports[i];
	spb->ports[i] = ports[i] + 1;
    }
    spa->cleanup_in = SESSION_TIMEOUT;
    spb->cleanup_in = -1;
    spa->rtcp = spb;
    spb->rtcp = NULL;
    spa->rtp = NULL;
    spb->rtp = spa;

    LIST_INSERT_HEAD(&session_set, spa, link);
    LIST_INSERT_HEAD(&session_set, spb, link);

    rebuild_tables();

    warnx("new session on a ports %d/%d created, tag %s",
      ports[0], ports[1], from_tag);

writeport:
    if (pidx >= 0 && ia[0] != NULL && ia[1] != NULL) {
	if (spa->pcount[pidx] == 0 && !(spa->addr[pidx] != NULL &&
	  ia[0]->sa_len == spa->addr[pidx]->sa_len &&
	  memcmp(ia[0], spa->addr[pidx], ia[0]->sa_len) == 0)) {
	    warnx("pre-filling %s's address with %s:%s",
	      (pidx == 0) ? "callee" : "caller", addr, port);
	    if (spa->addr[pidx] != NULL)
		free(spa->addr[pidx]);
	    spa->addr[pidx] = ia[0];
	    ia[0] = NULL;
	}
	if (spa->rtcp->pcount[pidx] == 0 && !(spa->rtcp->addr[pidx] != NULL &&
	  ia[1]->sa_len == spa->rtcp->addr[pidx]->sa_len &&
	  memcmp(ia[1], spa->rtcp->addr[pidx], ia[1]->sa_len) == 0)) {
	    if (spa->rtcp->addr[pidx] != NULL)
		free(spa->rtcp->addr[pidx]);
	    spa->rtcp->addr[pidx] = ia[1];
	    ia[1] = NULL;
	}
    }
    for (i = 0; i < 2; i++)
	if (ia[i] != NULL)
	    free(ia[i]);
    len = sprintf(buf, "%d\n", ports[0]);
doreply:
    while (write(controlfd, buf, len) == -1 && errno == EINTR);
    return;

nomem:
    warnx("can't allocate memory");
freeall:
    for (i = 0; i < 2; i++)
	if (ia[i] != NULL)
	    free(ia[i]);
    if (res != NULL)
	freeaddrinfo(res);
    if (spa != NULL) {
	if (spa->call_id != NULL)
	    free(spa->call_id);
	free(spa);
    }
    if (spb != NULL)
	free(spb);
    for (i = 0; i < 8; i++)
	if (fds[i] != -1)
	    close(fds[i]);
    return;
}

static void
usage(void)
{

    fprintf(stderr, "usage: rtpproxy [-2fv] [-l address] [-6 address] "
      "[-s path] [-t tos]\n");
    exit(1);
}

static void
fatsignal(int sig)
{

    warnx("got signal %d", sig);
    exit(0);
}

static void
ehandler(void)
{

    warnx("rtpproxy ended");
}

int
main(int argc, char **argv)
{
    int controlfd, i, readyfd, len, nodaemon, dmode, port, ridx, sidx, rebuild_pending;
    sigset_t set, oset;
    struct session *sp;
    union {
	struct sockaddr addr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } raddr;
    struct sockaddr_un ifsun;
    socklen_t rlen;
    struct itimerval tick;
    char buf[1024 * 8];
    char ch, *bh, *bh6;
    const char *cmd_sock;

    bh = NULL;
    bh6 = NULL;
    nodaemon = 0;

    cmd_sock = CMD_SOCK;
    tos = TOS;
    dmode = 0;

    while ((ch = getopt(argc, argv, "vf2l:6:s:t:")) != -1)
	switch (ch) {
	case 'f':
	    nodaemon = 1;
	    break;

	case 'l':
	    bh = optarg;
	    break;

	case '6':
	    use_ipv6 = 1;
	    bh6 = optarg;
	    break;

	case 's':
	    cmd_sock = optarg;
	    break;

	case 't':
	    tos = atoi(optarg);
	    break;

	case '2':
	    dmode = 1;
	    break;

	case 'v':
	    printf("%d\n", CPROTOVER);
	    exit(0);
	    break;

	case '?':
	default:
	    usage();
	}
    argc -= optind;
    argv += optind;

    setbindhost((struct sockaddr *)&bindaddr, AF_INET, bh);
    if (use_ipv6)
	setbindhost((struct sockaddr *)&bindaddr6, AF_INET6, bh6);

    unlink(cmd_sock);
    memset(&ifsun, '\0', sizeof ifsun);
#if !defined(__linux__) && !defined(__solaris__)
    ifsun.sun_len = strlen(cmd_sock);
#endif
    ifsun.sun_family = AF_LOCAL;
    strcpy(ifsun.sun_path, cmd_sock);
    controlfd = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (controlfd == -1)
	err(1, "can't create socket");
    setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &controlfd,
      sizeof controlfd);
    if (bind(controlfd, (struct sockaddr *)&ifsun, sizeof ifsun) < 0)
	err(1, "can't bind to a socket");
    if (listen(controlfd, 5) != 0)
	err(1, "can't listen on a socket");

#if !defined(__solaris__)
    if (nodaemon == 0) {
	if (daemon(0, 1) == -1)
	    err(1, "can't switch into daemon mode");
	    /* NOTREACHED */
	for (i = 0; i < FD_SETSIZE; i++)
	    if (i != controlfd)
		close(i);
    }
#endif

    atexit(ehandler);
    warnx("rtpproxy started, pid %d", getpid());
    signal(SIGHUP, fatsignal);
    signal(SIGINT, fatsignal);
    signal(SIGKILL, fatsignal);
    signal(SIGPIPE, fatsignal);
    signal(SIGTERM, fatsignal);
    signal(SIGXCPU, fatsignal);
    signal(SIGXFSZ, fatsignal);
    signal(SIGVTALRM, fatsignal);
    signal(SIGPROF, fatsignal);
    signal(SIGUSR1, fatsignal);
    signal(SIGUSR2, fatsignal);

    fds[0].fd = controlfd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    rebuild_tables();

    memset(&tick, 0, sizeof(tick));
    tick.it_interval.tv_sec = TIMETICK;
    tick.it_value.tv_sec = TIMETICK;
    signal(SIGALRM, SIG_IGN);
    setitimer(ITIMER_REAL, &tick, NULL);
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);

    signal(SIGALRM, alarmhandler);

    rebuild_pending = 0;
    while(1) {
	sigprocmask(SIG_UNBLOCK, &set, &oset);
	i = poll(fds, nsessions + 1, INFTIM);
	if (i < 0 && errno == EINTR)
	    continue;
	sigprocmask(SIG_BLOCK, &set, &oset);
	for (readyfd = 0; readyfd < nsessions + 1; readyfd++) {
	    if ((fds[readyfd].revents & POLLIN) == 0)
		continue;
	    if (readyfd == 0) {
		rlen = sizeof(ifsun);
		controlfd = accept(fds[readyfd].fd, (struct sockaddr *)&ifsun,
		  &rlen);
		if (controlfd == -1) {
		    warn(
		      "can't accept connection on control socket");
		    continue;
		}
		handle_command(controlfd);
		close(controlfd);
		/*
		 * Don't use continue here, because we have cleared all
		 * revents in rebuild_tables().
		 */
		break;
	    }
	    rlen = sizeof(raddr);
	    len = recvfrom(fds[readyfd].fd, buf, sizeof(buf), 0,
	      (struct sockaddr *)&raddr, &rlen);
	    if (len <= 0)
		continue;
	    sp = sessions[readyfd - 1];
	    for (i = 0; i < 4; i++) {
		if (fds[readyfd].fd == sp->fds[i]) {
		    ridx = i;
		    break;
		}
	    }

	    /*
	     * Can happen if we will have got packets both on IPv4 and IPv6
	     * ports, IPv6 is to be closed, while data can be still available
	     * from buffer.
	     */
	    if (i == 4)
		continue;

	    /*
	     * Once we received on IPv4 socket, close its IPv6 twin
	     * so that we don't waste system resources, and vice versa.
	     */
	    i = (ridx >= 2) ? ridx - 2 : ridx + 2;
	    if (sp->fds[i] != -1) {
		close(sp->fds[i]);
		sp->fds[i] = -1;
		if (sp->addr[i] != NULL) {
		    free(sp->addr[i]);
		    sp->addr[i] = NULL;
		}
		rebuild_pending = 1;
	    }
	    /* The same for RTP */
	    if (sp->rtp != NULL && sp->rtp->fds[i] != -1) {
		close(sp->rtp->fds[i]);
		sp->rtp->fds[i] = -1;
		if (sp->rtp->addr[i] != NULL) {
		    free(sp->rtp->addr[i]);
		    sp->rtp->addr[i] = NULL;
		}
		rebuild_pending = 1;
	    }
	    /* The same for RTCP */
	    if (sp->rtcp != NULL && sp->rtcp->fds[i] != -1) {
		close(sp->rtcp->fds[i]);
		sp->rtcp->fds[i] = -1;
		if (sp->rtcp->addr[i] != NULL) {
		    free(sp->rtcp->addr[i]);
		    sp->rtcp->addr[i] = NULL;
		}
		rebuild_pending = 1;
	    }

	    i = 0;
	    if (sp->addr[ridx] != NULL) {
		/* Check that the packet is authentic, drop if it isn't */
		if (memcmp(sp->addr[ridx], &raddr, rlen) != 0) {
		    if (sp->pcount[ridx] > 0)
			continue;
		    /* Signal that an address have to be updated */
		    i = 1;
		}
		sp->pcount[ridx]++;
	    } else {
		sp->pcount[ridx]++;
		sp->addr[ridx] = malloc(rlen);
		if (sp->addr[ridx] == NULL) {
		    sp->pcount[5]++;
		    warnx(
		      "can't allocate memory for remote address - "
		      "removing session");
		    if (sp->rtp == NULL)
			remove_session(sp);
		    else
			remove_session(sp->rtp);
		    rebuild_tables();
		    /*
		     * Don't use continue here, because we have cleared all
		     * revents in rebuild_tables().
		     */
		    break;
		}
		/* Signal that an address have to be updated. */
		i = 1;
	    }

	    /* Update recorded address if it's necessary. */
	    if (i != 0) {
		memcpy(sp->addr[ridx], &raddr, rlen);

		port = ntohs(((struct sockaddr_in *)&raddr)->sin_port);

		if (raddr.addr.sa_family == AF_INET)
		    warnx(
		      "%s's address filled in: %s:%d (%s)",
		      ((ridx % 2) == 0) ? "callee" : "caller",
		      inet_ntoa(raddr.addr4.sin_addr), port,
		      (sp->rtp == NULL) ? "RTP" : "RTCP");
		else
		    /* XXX: what is the analog of inet_ntoa(3) for IPv6? */
		    warnx(
		      "%s's address filled in: IPv6 (%s)",
		      ((ridx % 2) == 0) ? "callee" : "caller",
		      (sp->rtp == NULL) ? "RTP" : "RTCP");

		/*
		 * Check if we received RTP, while RTCP address is still
		 * empty - try to guess RTP at least, should be handy for
		 * non-NAT'ed clients.
		 */
		if (sp->rtcp != NULL && sp->rtcp->addr[ridx] == NULL) {
		    sp->rtcp->addr[ridx] = malloc(rlen);
		    if (sp->rtcp->addr[ridx] == NULL) {
			sp->pcount[5]++;
			warnx(
			  "can't allocate memory for remote address - "
			  "removing session");
			remove_session(sp);
			/*
			 * Don't use continue here, because we have cleared all
			 * revents in rebuild_tables().
			 */
			rebuild_tables();
			break;
		    }
		    memcpy(sp->rtcp->addr[ridx], &raddr, rlen);
		    ((struct sockaddr_in *)sp->rtcp->addr[ridx])->sin_port =
		      htons(port + 1);
		    warnx("guessing RTCP port "
		      "for %s to be %d",
		      ((ridx % 2) == 0) ? "callee" : "caller", port + 1);
		}
	    }

	    /* Select socket for sending packet out. */
	    if (ridx == 0 || ridx == 2)
		sidx = (sp->fds[1] != -1) ? 1 : 3;
	    else
		sidx = (sp->fds[0] != -1) ? 0 : 2;

	    if (sp->rtp == NULL)
		sp->cleanup_in = SESSION_TIMEOUT;
	    else
		sp->rtp->cleanup_in = SESSION_TIMEOUT;

	    /*
	     * Check that we have some address to which packet is to be
	     * sent out, drop otherwise.
	     */
	    if (sp->addr[sidx] == NULL) {
		sp->pcount[5]++;
		continue;
	    }

	    sp->pcount[4]++;
	    for (i = (dmode && len < LBR_THRS) ? 2 : 1; i > 0; i--) {
		if (sp->addr[sidx]->sa_family == AF_INET) {
		    sendto(sp->fds[sidx], buf, len, 0,
		      (struct sockaddr *)sp->addr[sidx],
		      sizeof(struct sockaddr_in));
		} else {
		    sendto(sp->fds[sidx], buf, len, 0,
		      (struct sockaddr *)sp->addr[sidx],
		      sizeof(struct sockaddr_in6));
		}
	    }
	}
	if (rebuild_pending != 0) {
	    rebuild_tables();
	    rebuild_pending = 0;
	}
    }

    exit(0);
}
