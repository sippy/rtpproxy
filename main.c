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
 * $Id: main.c,v 1.1 2004/01/05 21:03:36 sobomax Exp $
 *
 * History:
 * --------
 * 2003-09-21: Added IPv4/IPv6 translation, Jan Janak <jan@iptel.org>
 * 2003-10-14: Added ability to alter location of the command socket
 * 2003-10-18: Added ability to set TOS (type of service) for rtp packets
 *	       Added "double RTP mode"
 * 2003-12-10: Added support for relaying RTCP
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

struct session {
    LIST_ENTRY(session) link;
    struct sockaddr *addr[4];
    int fd;	/* IPv4 socket */
    int fd6;	/* IPv6 socket */
    int port;
    int cleanup_in;
    unsigned long pcount[3];
    char *call_id;
    struct session* rtcp;
    struct session* rtp;
};
static LIST_HEAD(, session) session_set = LIST_HEAD_INITIALIZER(&session_set);

static struct session *sessions[MAX_FDS];
static struct pollfd fds[MAX_FDS + 1];
static int nsessions;
static int use_ipv6;			/* IPv6 enabled/disabled */
static struct sockaddr_in bindaddr;	/* IPv4 socket address */
static struct sockaddr_in6 bindaddr6;	/* IPv6 socket address */
static int tos;
static int lastport = -1;

static void setbindhost(struct sockaddr *, int, const char *);
static void remove_session(struct session *);
static void rebuild_tables(void);
static void alarmhandler(int);
static int create_twinlistener(struct sockaddr *, int, int, int *, int *);
static int create_listener(int, int, int, int *, int *, int *, int *, int *);
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
    int i;

    i = 0;
    LIST_FOREACH(sp, &session_set, link) {
	fds[i + 1].fd = sp->fd;
	fds[i + 1].events = POLLIN;
	fds[i + 1].revents = 0;
	sessions[i] = sp;
	i++;
	if (use_ipv6) {
	    fds[i + 1].fd = sp->fd6;
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

    warnx("RTP stats: %lu in from addr1, %lu in from addr2, %lu relayed",
      sp->pcount[0], sp->pcount[1], sp->pcount[2]);
    warnx("RTCP stats: %lu in from addr1, %lu in from addr2, %lu relayed",
      sp->rtcp->pcount[0], sp->rtcp->pcount[1], sp->rtcp->pcount[2]);
    warnx("session on port %d is cleaned up", sp->port);
    close(sp->fd);
    close(sp->rtcp->fd);
    if (use_ipv6) {
	close(sp->fd6);
	close(sp->rtcp->fd6);
    }
    for (i = 0; i < 4; i++) {
	if (sp->addr[i] != NULL)
	    free(sp->addr[i]);
	if (sp->rtcp->addr[i] != NULL)
	    free(sp->rtcp->addr[i]);
    }
    if (sp->call_id != NULL)
	free(sp->call_id);
    LIST_REMOVE(sp, link);
    LIST_REMOVE(sp->rtcp, link);
    free(sp->rtcp);
    free(sp);
}

static int
create_twinlistener(struct sockaddr *ia, int pf, int port, int *fd1, int *fd2)
{
    struct sockaddr iac;
    int rval;
    int size;

    *fd1 = *fd2 = -1;

    *fd1 = socket(pf, SOCK_DGRAM, 0);
    if (*fd1 == -1) {
	warn("can't create %s socket", (pf == AF_INET) ? "IPv4" : "IPv6");
	return -1;
    }
    *fd2 = socket(pf, SOCK_DGRAM, 0);
    if (*fd2 == -1) {
	warn("can't create %s socket", (pf == AF_INET) ? "IPv4" : "IPv6");
	close(*fd1);
	return -1;
    }
    size = (pf == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    memcpy(&iac, ia, size);
    ((struct sockaddr_in *)&iac)->sin_port = htons(port);
    if (bind(*fd1, (struct sockaddr *)&iac, size) != 0) {
	if (errno != EADDRINUSE && errno != EACCES) {
	    warn("can't bind to the %s port %d", (pf == AF_INET) ? "IPv4" : "IPv6", port);
	    rval = -1;
	} else {
	    rval = -2;
	}
	goto failure;
    }
    memcpy(&iac, ia, size);
    ((struct sockaddr_in *)&iac)->sin_port = htons(port + 1);
    if (bind(*fd2, (struct sockaddr *)&iac, size) != 0) {
	if (errno != EADDRINUSE && errno != EACCES) {
	    warn("can't bind to the %s port %d", (pf == AF_INET) ? "IPv4" : "IPv6", port + 1);
	    rval = -1;
	} else {
	    rval = -2;
	}
	goto failure;
    }
    if (setsockopt(*fd1, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1)
	warn("unable to set TOS to %d", tos);
    if (setsockopt(*fd2, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1)
	warn("unable to set TOS to %d", tos);
    return 0;

failure:
    close(*fd1);
    close(*fd2);
    return rval;
}

static int
create_listener(int minport, int maxport, int startport, int *port, int *fda,
  int *fdb, int *fda6, int *fdb6)
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
	rval = create_twinlistener((struct sockaddr *)&bindaddr, AF_INET, *port, fda, fdb);
	if (rval != 0) {
	    if (rval == -1)
		break;
	    if (*port >= maxport)
		*port = minport - 2;
	    continue;
	}

	if (use_ipv6) {
	    rval = create_twinlistener((struct sockaddr *)&bindaddr6, AF_INET6, *port, fda6, fdb6);
	    if (rval != 0) {
		close(*fda);
		close(*fdb);
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
    int len, fda, fdb, fda6, fdb6, port, update, delete;
    char buf[1024 * 8];
    char *cp;
    struct session *spa, *spb;

    do {
	len = read(controlfd, buf, sizeof(buf) - 1);
    } while (len == -1 && errno == EINTR);
    if (len == -1)
	warn("can't read from control socket");
    if (len < 3)
	return;

    delete = 0;
    update = 0;
    switch (buf[0]) {
    case 'u':
    case 'U':
	update = 1;
	break;

    case 'l':
    case 'L':
	update = 0;
	break;

    case 'd':
    case 'D':
	delete = 1;
	break;

    default:
	return;
    }

    buf[len] = '\0';
    buf[sizeof(buf) - 1] = '\0';
    cp = buf + 2;
    len = strcspn(cp, "\r\n\t ");

    port = 0;
    LIST_FOREACH(spa, &session_set, link) {
	if (spa->rtcp == NULL || spa->call_id == NULL || strlen(spa->call_id) != len ||
	  memcmp(spa->call_id, cp, len) != 0)
	    continue;
	port = spa->port;
	if (delete == 1) {
	    warnx("forcefully deleting session on port %d", spa->port);
	    remove_session(spa);
	    rebuild_tables();
	    return;
	}
	spa->cleanup_in = SESSION_TIMEOUT;
	warnx("lookup on a port %d, session timer restarted", port);
	goto writeport;
    }
    if (delete == 1)
	return;

    if (update == 0)
	goto writeport;

    if (create_listener(PORT_MIN, PORT_MAX,
      lastport > 0 ? lastport + 1 : PORT_MIN, &port, &fda, &fdb, &fda6,
      &fdb6) == -1) {
	warnx("can't create listener");
	return;
    }
    lastport = port;

    spa = malloc(sizeof(*spa));
    if (spa == NULL) {
	warnx("can't allocate memory");
	if (use_ipv6) {
	    close(fda6);
	    close(fdb6);
	}
	close(fda);
	close(fdb);
	return;
    }
    spb = malloc(sizeof(*spb));
    if (spb == NULL) {
	warnx("can't allocate memory");
	free(spb);
	if (use_ipv6) {
	    close(fda6);
	    close(fdb6);
	}
	close(fda);
	close(fdb);
	return;
    }
    memset(spa, 0, sizeof(*spa));
    memset(spb, 0, sizeof(*spb));
    spa->call_id = malloc(len + 1);
    if (spa->call_id == NULL) {
	warnx("can't allocate memory");
	free(spa);
	free(spb);
	close(fda);
	close(fdb);
	if (use_ipv6) {
	    close(fda6);
	    close(fdb6);
	}
	return;
    }
    spb->call_id = spa->call_id;
    memcpy(spa->call_id, cp, len);
    spa->call_id[len] = '\0';
    spa->fd = fda;
    spb->fd = fdb;
    if (use_ipv6) {
	spa->fd6 = fda6;
	spb->fd6 = fdb6;
    }
    spa->port = port;
    spb->port = port + 1;
    spa->cleanup_in = SESSION_TIMEOUT;
    spb->cleanup_in = -1;
    spa->rtcp = spb;
    spb->rtcp = NULL;
    spa->rtp = NULL;
    spb->rtp = spa;

    LIST_INSERT_HEAD(&session_set, spa, link);
    LIST_INSERT_HEAD(&session_set, spb, link);

    rebuild_tables();

    warnx("new session on a port %d created", port);

writeport:
    len = sprintf(buf, "%d\n", port);
    while (write(controlfd, buf, len) == -1 && errno == EINTR);
}

static void
usage(void)
{

    errx(1, "usage: rtpproxy [-2f] [-l address] [-6 address] [-s path] [-t tos]");
}

int
main(int argc, char **argv)
{
    int controlfd, i, j, readyfd, len, nodaemon, dmode, port;
    sigset_t set, oset;
    struct session *sp;
    union {
	struct sockaddr addr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
    } raddr;
    struct sockaddr *saddr;
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

    while ((ch = getopt(argc, argv, "f2l:6:s:t:")) != -1)
	switch (ch) {
	case 'f':
	    nodaemon = 1;

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
	    saddr = NULL;
	    for (i = 0; i < 2; i++) {
		if (sp->addr[i] != NULL &&
		  sp->addr[i]->sa_family == raddr.addr.sa_family &&
		  memcmp(sp->addr[i], &raddr, rlen) == 0) {
		    j = (i == 0) ? 1 : 0;
		    sp->pcount[i]++;
		    if (sp->addr[j] != NULL)
			saddr = sp->addr[j];
		    else if (sp->addr[j + 2] != NULL)
			saddr = sp->addr[j + 2];
		    break;
		}
	    }
	    if (i == 2) {
		if (sp->addr[0] != NULL && sp->addr[1] != NULL)
		    continue;
		if (sp->addr[0] == NULL && sp->addr[1] == NULL &&
		  sp->addr[3] != NULL && memcmp(sp->addr[3], &raddr, rlen) == 0) {
		    i = 1;
		} else {
		    if (sp->addr[0] == NULL)
			i = 0;
		    else
			i = 1;
		}
		j = (i == 0) ? 1 : 0;
		sp->addr[i] = malloc(rlen);
		if (sp->addr[i] == NULL) {
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
		memcpy(sp->addr[i], &raddr, rlen);

		port = ntohs(((struct sockaddr_in *)&raddr)->sin_port);

		if (raddr.addr.sa_family == AF_INET)
		    warnx("addr%d filled in: %s:%d (%s)",
		      i + 1, inet_ntoa(raddr.addr4.sin_addr), port,
		      (sp->rtp == NULL) ? "RTP" : "RTCP");
		else
		    /* XXX: what is the analog of inet_ntoa(3) for IPv6? */
		    warnx("addr%d filled in: IPv6 (%s)",
		      i + 1, (sp->rtp == NULL) ? "RTP" : "RTCP");

		if (sp->rtcp != NULL && sp->rtcp->addr[i] == NULL && sp->rtcp->addr[i + 2] == NULL) {
		    sp->rtcp->addr[i + 2] = malloc(rlen);
		    if (sp->rtcp->addr[i + 2] == NULL) {
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
		    memcpy(sp->rtcp->addr[i + 2], &raddr, rlen);
		    ((struct sockaddr_in *)sp->rtcp->addr[i + 2])->sin_port =
		      htons(port + 1);
		    warnx("guessing RTCP port "
		      "for addr%d to be %d", i + 1, port + 1);
		}

		sp->pcount[i]++;
		if (sp->addr[j] != NULL)
		    saddr = sp->addr[j];
		else if (sp->addr[j + 2] != NULL)
		    saddr = sp->addr[j + 2];
	    }
	    sp->cleanup_in = SESSION_TIMEOUT;
	    if (saddr == NULL)
		continue;
	    sp->pcount[2]++;
	    for (i = (dmode && len < LBR_THRS) ? 2 : 1; i > 0; i--) {
		if (saddr->sa_family == AF_INET) {
		    sendto(sp->fd, buf, len, 0, (struct sockaddr *)saddr,
		      sizeof(struct sockaddr_in));
		} else {
		    sendto(sp->fd6, buf, len, 0, (struct sockaddr *)saddr,
		      sizeof(struct sockaddr_in6));
		}
	    }
	}
    }

    exit(0);
}
