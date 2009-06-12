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
 * $Id: rtpp_util.c,v 1.15 2009/06/12 19:10:08 sobomax Exp $
 *
 */

#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_util.h"
#include "rtpp_log.h"

double
getdtime(void)
{
    struct timeval timev;

    if (gettimeofday(&timev, NULL) == -1)
	return -1;

    return timev.tv_sec + ((double)timev.tv_usec) / 1000000.0;
}

void
dtime2ts(double dtime, uint32_t *ts_sec, uint32_t *ts_usec)
{

    *ts_sec = trunc(dtime);
    *ts_usec = round(1000000.0 * (dtime - ((double)*ts_sec)));
}

void
seedrandom(void)
{
    int fd;
    unsigned long junk;
    struct timeval tv;

    fd = open("/dev/random", O_RDONLY, 0);
    if (fd >= 0) {
	read(fd, &junk, sizeof(junk));
	close(fd);
    }

    gettimeofday(&tv, NULL);
    srandom((getpid() << 16) ^ tv.tv_sec ^ tv.tv_usec ^ junk);
}

int
drop_privileges(struct cfg *cf)
{

    if (cf->run_gname != NULL) {
	if (setgid(cf->run_gid) != 0) {
	    rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "can't set current group ID: %d", cf->run_gid);
	    return -1;
	}
    }
    if (cf->run_uname == NULL)
	return 0;
    if (setuid(cf->run_uid) != 0) {
	rtpp_log_ewrite(RTPP_LOG_ERR, cf->glog, "can't set current user ID: %d", cf->run_uid);
	return -1;
    }
    return 0;
}

void
init_port_table(struct cfg *cf)
{
    int i, j;
    uint16_t portnum;

    /* Generate linear table */
    cf->port_table_len = ((cf->port_max - cf->port_min) / 2) + 1;
    portnum = cf->port_min;
    for (i = 0; i < cf->port_table_len; i += 1) {
	cf->port_table[i] = portnum;
	portnum += 2;
    }
#if !defined(SEQUENTAL_PORTS)
    /* Shuffle elements ramdomly */
    for (i = 0; i < cf->port_table_len; i += 1) {
	j = random() % cf->port_table_len;
	portnum = cf->port_table[i];
	cf->port_table[i] = cf->port_table[j];
	cf->port_table[j] = portnum;
    }
#endif
    /* Set the last used element to be the last element */
    cf->port_table_idx = cf->port_table_len - 1;
}

/*
 * Portable strsep(3) implementation, borrowed from FreeBSD. For license
 * and other information see:
 *
 * $FreeBSD: src/lib/libc/string/strsep.c,v 1.6 2007/01/09 00:28:12 imp Exp $
 */
char *
rtpp_strsep(char **stringp, const char *delim)
{
    char *s;
    const char *spanp;
    int c, sc;
    char *tok;

    if ((s = *stringp) == NULL)
	return (NULL);
    for (tok = s;;) {
	c = *s++;
	spanp = delim;
	do {
	    if ((sc = *spanp++) == c) {
		if (c == 0)
		    s = NULL;
		else
		    s[-1] = 0;
		*stringp = s;
		return (tok);
	    }
	} while (sc != 0);
    }
    /* NOTREACHED */
}

/*
 * Portable daemon(3) implementation, borrowed from FreeBSD. For license
 * and other information see:
 *
 * $FreeBSD: src/lib/libc/gen/daemon.c,v 1.8 2007/01/09 00:27:53 imp Exp $
 */
int
rtpp_daemon(int nochdir, int noclose)
{
    struct sigaction osa, sa;
    int fd;
    pid_t newgrp;
    int oerrno;
    int osa_ok;

    /* A SIGHUP may be thrown when the parent exits below. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    osa_ok = sigaction(SIGHUP, &sa, &osa);

    switch (fork()) {
    case -1:
        return (-1);
    case 0:
        break;
    default:
        _exit(0);
    }

    newgrp = setsid();
    oerrno = errno;
    if (osa_ok != -1)
        sigaction(SIGHUP, &osa, NULL);

    if (newgrp == -1) {
        errno = oerrno;
        return (-1);
    }

    if (!nochdir)
        (void)chdir("/");

    if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        (void)dup2(fd, STDIN_FILENO);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        if (fd > 2)
            (void)close(fd);
    }
    return (0);
}

static int8_t hex2char[128] = {
    -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,   1,   2,   3,   4,   5,   6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int
url_unquote(uint8_t *buf, int len)
{
    int outlen;
    uint8_t *cp;

    outlen = len;
    while (len > 0) {
        cp = memchr(buf, '%', len);
        if (cp == NULL)
            return (outlen);
        if (cp - buf + 2 > len)
            return (-1);
        if (cp[1] > 127 || cp[2] > 127 ||
          hex2char[cp[1]] == -1 || hex2char[cp[2]] == -1)
            return (-1);
        cp[0] = (hex2char[cp[1]] << 4) | hex2char[cp[2]];
        len -= cp - buf + 3;
        if (len > 0)
            memmove(cp + 1, cp + 3, len);
        buf = cp + 1;
        outlen -= 2;
    }
    return (outlen);
}
