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
 * $Id: main.c,v 1.7 2004/02/17 18:02:17 sobomax Exp $
 *
 * History:
 * --------
 * 2003-09-21: Added IPv4/IPv6 translation, Jan Janak <jan@iptel.org>
 *
 * 2003-10-14: Added ability to alter location of the command socket
 *
 * 2003-10-18: Added ability to set TOS (type of service) for rtp packets
 *
 *	       Added "double RTP mode"
 *
 * 2003-12-10: Added support for relaying RTCP
 *
 * 2004-01-07: Major overhaul - now two ports are allocated for each session,
 *	       to make RTCP working properly, internal reorganisation,
 *	       new incompatible version of the command protocol, etc.
 *
 *	       New command is added `V', which reports supported version of
 *	       of the command protocol.
 *
 * 2004-02-09: Added ability to record rtp sessions (-r option)
 *
 *	       Added new "bridge mode", in this mode rtpproxy acts as a
 *	       bridge, forwarding packets between two addresses, which can
 *	       for example be assigned to two physical interfaces, one LAN
 *	       and the second one is WAN, or to the same interface but one
 *	       address can be IPv4 and the second one is IPv6, etc. Requires
 *	       updated natelper module to utilise this functionality.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/uio.h>
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
#include <limits.h>
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

#if !defined(ACCESSPERMS)
#define	ACCESSPERMS (S_IRWXU|S_IRWXG|S_IRWXO)
#endif
#if !defined(DEFFILEMODE)
#define	DEFFILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
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

#define	in_nullhost(x)	((x)->sin_addr.s_addr == INADDR_ANY)
#define	in_hosteq(s, t)	((s)->sin_addr.s_addr == (t)->sin_addr.s_addr)
#define	in6_hosteq(s, t) \
  (memcmp(&(s)->sin6_addr.s6_addr[0], &(t)->sin6_addr.s6_addr[0], sizeof(struct in6_addr)) == 0)

#if !defined(SA_LEN)
#define	SA_LEN(sa)	(((sa)->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

struct session {
    LIST_ENTRY(session) link;
    struct sockaddr *addr[4];
    struct sockaddr *laddr[2];
    int cleanup_in;
    unsigned long pcount[6];
    char *call_id;
    char *tag;
    struct session* rtcp;
    struct session* rtp;
    /* Descriptors, first pair for IPv4, the second one for IPv6 */
    int fds[4];
    int ports[2];
    /* Session is complete, that is we received both request and reply */
    int complete;
    int asymmetric[2];
    int rfds[2];
};
static LIST_HEAD(, session) session_set = LIST_HEAD_INITIALIZER(&session_set);

struct pkt_hdr {
    struct sockaddr addr;	/* Source address */
    struct timeval time;	/* Time of arrival */
    int plen;			/* Length of following RTP/RTCP packet */
};

static struct session *sessions[MAX_FDS];
static struct pollfd fds[MAX_FDS + 1];
static int nsessions;
static int bmode = 0;			/* Bridge mode */
static int use_ipv6;			/* IPv6 enabled/disabled */

/*
 * The first address is for external interface, the second one - for
 * internal one. Could be the same, in this case there is no bridge
 * mode enabled.
 */
static struct sockaddr_in *bindaddr[2];	/* IPv4 socket addresses */
static struct sockaddr_in6 *bindaddr6[2];/* IPv6 socket addresses */

static int tos;
static int lastport[2] = {PORT_MIN - 1, PORT_MIN - 1};
static const char *rdir = NULL;

static const char *addr2char(struct sockaddr *);
static void setbindhost(struct sockaddr *, int, const char *);
static void remove_session(struct session *);
static void rebuild_tables(void);
static void alarmhandler(int);
static int create_twinlistener(struct sockaddr *, int, int, int *);
static int create_listener(struct sockaddr_in *, struct sockaddr_in6 *,
  int, int, int, int *, int *);
static int ropen(struct session *, const char *, int);
static void rwrite(struct session *, int, struct sockaddr *, void *, int);
static void handle_command(int);
static void usage(void);

static const char *
addr2char(struct sockaddr *ia)
{
    static char buf[256];
    void *addr;

    switch (ia->sa_family) {
    case AF_INET:
	addr = &(((struct sockaddr_in *)ia)->sin_addr);
	break;

    case AF_INET6:
	addr = &(((struct sockaddr_in6 *)ia)->sin6_addr);
	break;

    default:
	return NULL;
    }

    return inet_ntop(ia->sa_family, addr, buf, sizeof(buf));
}

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
alarmhandler(int sig __attribute__ ((unused)))
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

    warnx("RTP stats: %lu in from callee, %lu in from caller, %lu relayed, "
      "%lu dropped",
      (sp->pcount[0] > 0) ? sp->pcount[0] : sp->pcount[2],
      (sp->pcount[1] > 0) ? sp->pcount[1] : sp->pcount[3],
      sp->pcount[4], sp->pcount[5]);
    warnx("RTCP stats: %lu in from callee, %lu in from caller, %lu relayed, "
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
    for (i = 0; i < 2; i++) {
	if (sp->rfds[i] != -1)
	    close(sp->rfds[i]);
	if (sp->rtcp->rfds[i] != -1)
	    close(sp->rtcp->rfds[i]);
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
create_listener(struct sockaddr_in *ia, struct sockaddr_in6 *ia6,
    int minport, int maxport, int startport, int *port, int *fds)
{
    int i, init, rval;

    /* make sure that {min,max,start}port is even */
    if ((minport & 0x1) != 0)
	minport++;
    if ((maxport & 0x1) != 0)
	maxport--;
    if ((startport & 0x1) != 0)
	startport++;

    for (i = 0; i < 4; i++)
	fds[i] = -1;

    init = 0;
    if (startport < minport || startport > maxport)
	startport = minport;
    for (*port = startport; *port != startport || init == 0; (*port) += 2) {
	init = 1;
	if (ia != NULL) {
	    rval = create_twinlistener((struct sockaddr *)ia, AF_INET,
		*port, fds);
	    if (rval != 0) {
		if (rval == -1)
		    break;
		if (*port >= maxport)
		    *port = minport - 2;
		continue;
	    }
	}

	if (ia6 != NULL) {
	    rval = create_twinlistener((struct sockaddr *)ia6, AF_INET6,
		*port, fds + 2);
	    if (rval != 0) {
		if (ia != NULL) {
		    close(fds[0]);
		    close(fds[1]);
		    fds[0] = fds[1] = -1;
		}
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

static int
ropen(struct session *sp, const char *dir, int orig)
{
    char path[PATH_MAX + 1];
    int rval;

    sprintf(path, "%s/%s=%s", dir, sp->call_id, sp->tag);
    rval = mkdir(path, ACCESSPERMS);
    if (rval == -1 && errno != EEXIST) {
	warn("can't create directory %s",
	  path);
	return -1;
    }

    sprintf(path, "%s/%s=%s/%c.%s", dir, sp->call_id, sp->tag,
      (orig != 0) ? 'o' : 'a', (sp->rtcp != NULL) ? "rtp" : "rtcp");
    rval = open(path, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (rval == -1) {
	warn("can't open file %s for writing",
	  path);
	return -1;
    }
    return rval;
}

static void
rwrite(struct session *sp, int idx, struct sockaddr *saddr, void *buf, int len)
{
    struct iovec v[2];
    struct pkt_hdr hdr;
    int rval;

    memset(&hdr, 0, sizeof(hdr));

    rval = gettimeofday(&hdr.time, NULL);
    if (rval == -1) {
	warn("can't get current time");
	goto fatal_error;
    }
    memcpy(&hdr.addr, saddr, SA_LEN(saddr));
    hdr.plen = len;

    v[0].iov_base = (void *)&hdr;
    v[0].iov_len = sizeof(hdr);
    v[1].iov_base = buf;
    v[1].iov_len = len;

    while ((rval = writev(sp->rfds[idx], v, 2)) == -1 && errno == EINTR);
    if (rval != -1)
	return;

    warn("error while recording session (%s)",
      (sp->rtcp != NULL) ? "RTP" : "RTCP");
fatal_error:
    close(sp->rfds[idx]);
    sp->rfds[idx] = -1;
}

static void
handle_command(int controlfd)
{
    int len, delete, argc, i, pidx, request, response, asymmetric, external;
    int fds[8], ports[2];
    char buf[1024 * 8];
    char *cp, *call_id, *from_tag, *to_tag, *addr, *port;
    struct session *spa, *spb;
    char **ap, *argv[10];
    struct sockaddr *ia[2], *lia[2];
    struct addrinfo hints, *res;

    (void *)ia[0] = (void *)ia[1] = (void *)res = spa = spb = NULL;
    lia[0] = lia[1] = NULL;
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

    request = response = delete = 0;
    addr = port = NULL;
    switch (argv[0][0]) {
    case 'u':
    case 'U':
	if (argc < 5 || argc > 6) {
	    warnx("command syntax error");
	    return;
	}
	request = 1;
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
	response = 1;
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

    if (request != 0 || response != 0) {
	if (argv[0][1] == 'a' || argv[0][1] == 'A' || bmode != 0)
	    asymmetric = 1;
	else
	    asymmetric = 0;

	if ((argv[0][1] == 'i' || argv[0][1] == 'I') && bmode != 0)
	    external = 0;
	else
	    external = 1;
    }

    if (delete == 0 && addr != NULL && port != NULL && strlen(addr) >= 7) {
	int n;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;/* Address is numeric */
	hints.ai_family = AF_INET;	/* Protocol family, so far IPv4 only */
	hints.ai_socktype = SOCK_DGRAM;	/* UDP */

	if ((n = getaddrinfo(addr, port, &hints, &res)) == 0) {
	    if (!in_nullhost((struct sockaddr_in *)res->ai_addr)) {
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
	    i = (request == 0) ? 1 : 0;
	else if (to_tag != NULL && strcmp(spa->tag, to_tag) == 0)
	    i = (request == 0) ? 0 : 1;
	else
	    continue;
	if (delete == 1) {
	    warnx("forcefully deleting session on ports %d/%d", spa->ports[0],
	      spa->ports[1]);
	    remove_session(spa);
	    rebuild_tables();
	    return;
	}
	ports[0] = spa->ports[i];
	if (bmode != 0)
	    lia[0] = spa->laddr[i];
	else
	    lia[0] = spa->laddr[0];
	pidx = (i == 0) ? 1 : 0;
	spa->cleanup_in = SESSION_TIMEOUT;
	warnx("lookup on a ports %d/%d, session timer restarted", spa->ports[0],
	  spa->ports[1]);
	if (response == 1 && spa->complete == 0)
	    spa->complete = spa->rtcp->complete = 1;
	goto writeport;
    }
    if (delete == 1) {
	warnx("delete request failed: session %s, tags %s/%s not found", call_id,
	  from_tag, to_tag != NULL ? to_tag : "NONE");
	return;
    }

    if (response == 1) {
	warnx("lookup request: session %s, tags %s/%s not found", call_id,
	  from_tag, to_tag != NULL ? to_tag : "NONE");
	pidx = -1;
	goto writeport;
    }

    warnx("new session %s, tag %s requested", call_id,
      from_tag);

    if (bmode == 0) {
	for (i = 0; i < 2; i++) {
	    if (create_listener(bindaddr[0], bindaddr6[0], PORT_MIN, PORT_MAX,
	      lastport[0], &ports[i], fds + i * 4) == -1) {
		warnx("can't create listener");
		goto freeall;
	    }
	    lastport[0] = ports[i];
	}
    } else {
	int j;

	for (i = 0; i < 2; i++) {
	    j = (external == 0) ? i : 1 - i;
	    if (create_listener(bindaddr[j], bindaddr6[j],
	      PORT_MIN, PORT_MAX, lastport[j], &ports[i], fds + i * 4) == -1) {
		warnx("can't create listener");
		goto freeall;
	    }
	    lia[i] = (bindaddr[j] != NULL) ?
	      (void *)bindaddr[j] : (void *)bindaddr6[j];
	    lastport[j] = ports[i];
	}
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
	spa->laddr[i] = lia[i];
	spb->laddr[i] = lia[i];
	spa->rfds[i] = -1;
	spb->rfds[i] = -1;
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
    if (pidx >= 0) {
	if (ia[0] != NULL && ia[1] != NULL) {
	    if (spa->pcount[pidx] == 0 && !(spa->addr[pidx] != NULL &&
	      SA_LEN(ia[0]) == SA_LEN(spa->addr[pidx]) &&
	      memcmp(ia[0], spa->addr[pidx], SA_LEN(ia[0])) == 0)) {
		warnx("pre-filling %s's address with %s:%s",
		  (pidx == 0) ? "callee" : "caller", addr, port);
		if (spa->addr[pidx] != NULL)
		    free(spa->addr[pidx]);
		spa->addr[pidx] = ia[0];
		ia[0] = NULL;
	    }
	    if (spa->rtcp->pcount[pidx] == 0 && !(spa->rtcp->addr[pidx] != NULL &&
	      SA_LEN(ia[1]) == SA_LEN(spa->rtcp->addr[pidx]) &&
	      memcmp(ia[1], spa->rtcp->addr[pidx], SA_LEN(ia[1])) == 0)) {
		if (spa->rtcp->addr[pidx] != NULL)
		    free(spa->rtcp->addr[pidx]);
		spa->rtcp->addr[pidx] = ia[1];
		ia[1] = NULL;
	    }
	}
	spa->asymmetric[pidx % 2] = spa->rtcp->asymmetric[pidx % 2] = asymmetric;
	if (rdir != NULL) {
	    if (spa->rfds[pidx % 2] == -1)
		spa->rfds[pidx % 2] = ropen(spa, rdir, pidx % 2);
	    if (spa->rtcp->rfds[pidx % 2] == -1)
		spa->rtcp->rfds[pidx % 2] = ropen(spa->rtcp, rdir, pidx % 2);
	}
    }
    for (i = 0; i < 2; i++)
	if (ia[i] != NULL)
	    free(ia[i]);
    if (lia[0] == NULL)
	len = sprintf(buf, "%d\n", ports[0]);
    else
	len = sprintf(buf, "%d %s\n", ports[0], addr2char(lia[0]));
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

    fprintf(stderr, "usage: rtpproxy [-2fv] [-l addr1[/addr2]] "
      "[-6 addr1[/addr2]] [-s path] [-t tos] [-r directory]\n");
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
    int controlfd, i, readyfd, len, nodaemon, dmode, port, ridx, sidx;
    int rebuild_pending;
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
    char ch, *bh[2], *bh6[2];
    const char *cmd_sock;

    bh[0] = bh[1] = bh6[0] = bh6[1] = NULL;
    rdir = NULL;
    nodaemon = 0;

    cmd_sock = CMD_SOCK;
    tos = TOS;
    dmode = 0;

    while ((ch = getopt(argc, argv, "vf2l:6:s:t:r:")) != -1)
	switch (ch) {
	case 'f':
	    nodaemon = 1;
	    break;

	case 'l':
	    bh[0] = optarg;
	    bh[1] = strchr(bh[0], '/');
	    if (bh[1] != NULL) {
		*bh[1] = '\0';
		bh[1]++;
		bmode = 1;
	    }
	    break;

	case '6':
	    use_ipv6 = 1;
	    bh6[0] = optarg;
	    bh6[1] = strchr(bh6[0], '/');
	    if (bh6[1] != NULL) {
		*bh6[1] = '\0';
		bh6[1]++;
		bmode = 1;
	    }
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

	case 'r':
	    rdir = optarg;
	    break;

	case '?':
	default:
	    usage();
	}
    argc -= optind;
    argv += optind;

    for (i = 0; i < 2; i++) {
	if (bh[i] != NULL && *bh[i] == '\0')
	    bh[i] = NULL;
	if (bh6[i] != NULL && *bh6[i] == '\0')
	    bh6[i] = NULL;
    }

    if (bmode != 0) {
	if (bh[0] != NULL && bh6[0] != NULL)
	    errx(1, "either IPv4 or IPv6 should be configured for external "
	      "interface in bridging mode, not both");
	if (bh[1] != NULL && bh6[1] != NULL)
	    errx(1, "either IPv4 or IPv6 should be configured for internal "
	      "interface in bridging mode, not both");
	i = ((bh[0] == NULL) ? 0 : 1) + ((bh[1] == NULL) ? 0 : 1) +
	  ((bh6[0] == NULL) ? 0 : 1) + ((bh6[1] == NULL) ? 0 : 1);
	if (i != 2)
	    errx(1, "incomplete configuration of the bridging mode - exactly "
	      "2 listen addresses required, %d provided", i);
    }

    for (i = 0; i < 2; i++) {
	bindaddr[i] = NULL;
	bindaddr6[i] = NULL;
	if (bh[i] != NULL) {
	    bindaddr[i] = alloca(sizeof(*bindaddr[i]));
	    setbindhost((struct sockaddr *)bindaddr[i], AF_INET, bh[i]);
	}
	if (bh6[i] != NULL) {
	    bindaddr6[i] = alloca(sizeof(*bindaddr6[i]));
	    setbindhost((struct sockaddr *)bindaddr6[i], AF_INET6, bh6[i]);
	}
    }

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
	for (i = 0; i < (int)FD_SETSIZE; i++)
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
		    warn("can't accept connection on control socket");
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

	    if (sp->complete == 0)
		continue;

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
		if (sp->asymmetric[ridx % 2] == 0 && bmode == 0) {
			if (memcmp(sp->addr[ridx], &raddr, rlen) != 0) {
			    if (sp->pcount[ridx] > 0)
				continue;
			    /* Signal that an address have to be updated */
			    i = 1;
			}
		} else {
		    /* For asymmetric clients or in bridged mode don't check port */
		    if (raddr.addr.sa_family == AF_INET) {
			if (!in_hosteq((struct sockaddr_in *)sp->addr[ridx], (struct sockaddr_in *)&raddr))
			    continue;
		    } else {
			if (!in6_hosteq((struct sockaddr_in6 *)sp->addr[ridx], (struct sockaddr_in6 *)&raddr))
			    continue;
		    }
		}
		sp->pcount[ridx]++;
	    } else {
		sp->pcount[ridx]++;
		sp->addr[ridx] = malloc(rlen);
		if (sp->addr[ridx] == NULL) {
		    sp->pcount[5]++;
		    warnx("can't allocate memory for remote address - "
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
	    if (i != 0 && sp->asymmetric[ridx % 2] == 0) {
		memcpy(sp->addr[ridx], &raddr, rlen);

		port = ntohs(((struct sockaddr_in *)&raddr)->sin_port);

		warnx("%s's address filled in: %s:%d (%s)",
		  ((ridx % 2) == 0) ? "callee" : "caller",
		  addr2char((struct sockaddr *)&raddr), port,
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
			warnx("can't allocate memory for remote address - "
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
		goto do_record;
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
do_record:
	    if (sp->rfds[ridx % 2] != -1)
		rwrite(sp, ridx % 2, (struct sockaddr *)&raddr, buf, len);
	}
	if (rebuild_pending != 0) {
	    rebuild_tables();
	    rebuild_pending = 0;
	}
    }

    exit(0);
}
