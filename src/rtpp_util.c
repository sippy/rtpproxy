/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2023 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_util.h"
#include "rtpp_log_obj.h"
#include "rtpp_runcreds.h"
#include "rtpp_debug.h"

#if defined(RTPP_DEBUG)
#include "rtpp_coverage.h"
#endif

void
seedrandom(void)
{
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    int fd;
    unsigned long junk;
    struct timeval tv;

    fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd >= 0) {
	read(fd, &junk, sizeof(junk));
	close(fd);
    } else {
        junk = 0;
    }

    gettimeofday(&tv, NULL);
    srandom((unsigned int)(getpid() << 14) ^ tv.tv_sec ^ tv.tv_usec ^ junk);
#else
    srandom(42);
#endif
}

int
set_rlimits(const struct rtpp_cfg *cfsp)
{
    struct rlimit rlp;

    if (getrlimit(RLIMIT_CORE, &rlp) < 0) {
        RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "getrlimit(RLIMIT_CORE)");
        return (-1);
    }
    rlp.rlim_cur = RLIM_INFINITY;
    rlp.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rlp) < 0) {
        RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "setrlimit(RLIMIT_CORE)");
        return (-1);
    }
    return (0);
}

int
drop_privileges(const struct rtpp_cfg *cfsp)
{

    if (cfsp->runcreds->gname != NULL) {
	if (setgid(cfsp->runcreds->gid) != 0) {
	    RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "can't set current group ID: %d",
	      (int)cfsp->runcreds->gid);
	    return -1;
	}
    }
    if (cfsp->runcreds->uname == NULL)
	return 0;
    if (setuid(cfsp->runcreds->uid) != 0) {
	RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "can't set current user ID: %d",
	  (int)cfsp->runcreds->uid);
	return -1;
    }
    return 0;
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

static void __attribute__ ((noreturn))
rtpp_daemon_parent(const struct rtpp_daemon_rope *rp)
{
    char buf[rp->msglen];
    int r, e = 0;

    do {
        r = read(rp->pipe, buf, rp->msglen);
    } while (r < 0 && errno == EINTR);
    if (r < rp->msglen || memcmp(buf, rp->ok_msg, rp->msglen) != 0) {
        e = 1;
    }
#if defined(RTPP_DEBUG)
    rtpp_gcov_flush();
#endif
    _exit(e);
}

int
rtpp_daemon_rel_parent(const struct rtpp_daemon_rope *rp)
{
    int r;

    do {
        r = write(rp->pipe, rp->ok_msg, rp->msglen);
    } while (r < 0 && errno == EINTR);
    (void)close(rp->pipe);
    if (r == rp->msglen)
        return (0);
    return (-1);
}

/*
 * Portable daemon(3) implementation, derived from FreeBSD. For license
 * and other information see:
 *
 * $FreeBSD: src/lib/libc/gen/daemon.c,v 1.8 2007/01/09 00:27:53 imp Exp $
 *
 * This version has since been extended to permit simple protocol
 * to be implemented between parent and a child to keep parent
 * alive until child done everything it needs to do in order to get
 * up and running, so that any error condition can be propagated
 * back.
 */

struct rtpp_daemon_rope
rtpp_daemon(int nochdir, int noclose, int noredir)
{
    struct sigaction osa, sa;
    int fd;
    pid_t newgrp;
    int oerrno;
    int osa_ok;
    int ropefd[2];
    struct rtpp_daemon_rope res = {.result = 0, .ok_msg = "OK", .msglen = 2};

    if (!noclose) {
        fd = open("/dev/null", O_RDWR, 0);
        if (fd < 0)
            goto fail;
    }
    if (pipe(ropefd) != 0) {
        goto e0;
    }
    /* A SIGHUP may be thrown when the parent exits below. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    osa_ok = sigaction(SIGHUP, &sa, &osa);

    switch (fork()) {
    case -1:
        goto e1;
    case 0:  /*  child */
        (void)close(ropefd[0]);
        res.pipe = ropefd[1];
        break;
    default: /* parent */
        (void)close(ropefd[1]);
        res.pipe = ropefd[0];
        rtpp_daemon_parent(&res);
        /* noreturn */
    }

    newgrp = setsid();
    oerrno = errno;
    if (osa_ok != -1)
        sigaction(SIGHUP, &osa, NULL);

    if (newgrp == -1) {
        errno = oerrno;
        goto child_fail;
    }

    if (!nochdir)
        (void)chdir("/");

    if (!noclose) {
        if (fd != STDIN_FILENO) {
            if (dup2(fd, STDIN_FILENO) < 0) {
                (void)close(fd);
                goto child_fail;
            }
            (void)close(fd);
        }
#if !defined(RTPP_DEBUG)
	if (!noredir) {
            if (dup2(STDIN_FILENO, STDOUT_FILENO) < 0) {
                goto child_fail;
            }
            if (dup2(STDIN_FILENO, STDERR_FILENO) < 0) {
                goto child_fail;
            }
        }
#endif
    }
    return (res);
child_fail:
    (void)close(res.pipe);
    goto fail;
e1:
    (void)close(ropefd[0]);
    (void)close(ropefd[1]);
e0:
    if (!noclose)
        (void)close(fd);
fail:
    return ((struct rtpp_daemon_rope){.result = -1});
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
url_unquote2(const char *ibuf, char *obuf, int len)
{
    int outlen;
    uint8_t *ocp = (uint8_t *)obuf;
    const unsigned char *cp, *endp;

    outlen = len;
    endp = (const unsigned char *)ibuf + len;
    for (cp = (const unsigned char *)ibuf; cp < endp; cp++, ocp++) {
        switch (cp[0]) {
        case '%':
            if (cp + 2 > endp)
                return (-1);
            if (cp[1] > 127 || cp[2] > 127 ||
              hex2char[cp[1]] == -1 || hex2char[cp[2]] == -1)
                return (-1);
            ocp[0] = (hex2char[cp[1]] << 4) | hex2char[cp[2]];
            cp += 2;
            outlen -= 2;
            break;

        case '+':
            ocp[0] = ' ';
            break;

        default:
            if (ocp != cp)
                ocp[0] = cp[0];
            break;
        }
    }
    return (outlen);
}

int
url_unquote(unsigned char *buf, int len)
{

    return (url_unquote2((char *)buf, (char *)buf, len));
}

int
url_quote(const char *ibuf, char *obuf, int ilen, int olen) {
    const char *hex = "0123456789ABCDEF";
    const unsigned char *cp;
    unsigned char *ocp = (unsigned char *)obuf;
    int outlen = 0;

    for (cp = (const unsigned char *)ibuf; ilen-- > 0; cp++) {
        if ((*cp >= 'A' && *cp <= 'Z') || (*cp >= 'a' && *cp <= 'z') ||
          (*cp >= '0' && *cp <= '9') || *cp == '-' || *cp == '_' ||
          *cp == '.' || *cp == '~') {
            if ((olen - outlen) == 0)
                return -1;
            *ocp++ = *cp;
            outlen++;
        } else {
            if ((olen - outlen) < 3)
                return -1;
            *ocp++ = '%';
            *ocp++ = hex[*cp >> 4];
            *ocp++ = hex[*cp & 0x0F];
            outlen += 3;
        }
    }
    return outlen;
}

enum atoi_rval
atoi_safe_sep(const char *s, int *res, char sep, const char * *next)
{
    int rval;
    char *cp;

    rval = strtol(s, &cp, 10);
    if (cp == s || *cp != sep) {
        return (ATOI_NOTINT);
    }
    *res = rval;
    if (next != NULL) {
        *next = cp + 1;
    }
    return (ATOI_OK);
}

enum atoi_rval
atoi_safe(const char *s, int *res)
{

    return (atoi_safe_sep(s, res, '\0', NULL));
}

enum atoi_rval
atoi_saferange(const char *s, int *res, int min, int max)
{
    int rval;

    if (atoi_safe(s, &rval)) {
        return (ATOI_NOTINT);
    }
    if (rval < min || (max >= min && rval > max)) {
        return (ATOI_OUTRANGE);
    }
    *res = rval;
    return (ATOI_OK);
}

#if defined(_SC_CLK_TCK) && !defined(__FreeBSD__)
#if defined(LINUX_XXX)
static int
rtpp_get_sched_hz_linux(void)
{
    int fd, rlen;
    char buf[16], *cp;
    int64_t n;

    fd = open("/proc/sys/kernel/sched_min_granularity_ns", O_RDONLY, 0);
    if (fd == -1) {
        return (-1);
    }
    rlen = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (rlen <= 0) {
        return (-1);
    }
    buf[rlen] = '\0'; 
    n = strtol(buf, &cp, 10);
    if (cp == buf) {
        return (-1);
    }
    if (n <= 0) {
        return (-1);
    }
    return ((int64_t)1000000000 / n);
}
#endif

int
rtpp_get_sched_hz(void)
{
    int sched_hz;

#if defined (LINUX_XXX)
    sched_hz = rtpp_get_sched_hz_linux();
    if (sched_hz > 0) {
        return (sched_hz);
    }
#endif
    sched_hz = sysconf(_SC_CLK_TCK);
    return (sched_hz > 0 ? sched_hz : 100);
}
#else
int
rtpp_get_sched_hz(void)
{
    int sched_hz;
    size_t len;

    len = sizeof(sched_hz);
    if (sysctlbyname("kern.hz", &sched_hz, &len, NULL, 0) == -1 || sched_hz <= 0)
        return 1000;
    return (sched_hz);
}
#endif

#ifndef HAVE_STRLCPY
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

#endif /* !HAVE_STRLCPY */

#define populate(n, t) (~((t)0) / 255 * (n))
#define haszero(v) ~(((((v) & populate(0x7f, typeof(v))) + populate(0x7f, typeof(v))) | \
  (v)) | populate(0x7f, typeof(v)))

void
rtpp_strsplit(char *ibuf, char *mbuf, size_t dlen, size_t blen)
{
        const uint64_t sep_masks[4] = {
                populate('\t', uint64_t),
                populate('\n', uint64_t),
                populate('\r', uint64_t),
                populate(' ', uint64_t)
        };

        RTPP_DBG_ASSERT(blen >= dlen && (blen % sizeof(uint64_t)) == 0);

        uint64_t *cp = (uint64_t *)ibuf;
        uint64_t *obp = (uint64_t *)mbuf;

        for (int i = 0; i < dlen; i += sizeof(uint64_t)) {
                uint64_t ww;
                uint64_t ow = populate(0xff, uint64_t);
                ww = *cp;
                for (int j = 0; j < 4; j++) {
                        ow &= ~(haszero(ww ^ sep_masks[j]) / 0x80 * 0xff);
                }
                *obp = ow;
                ww &= ow;
                *cp = ww;
                obp += 1;
                cp += 1;
        }
}

void
generate_random_string(char *buffer, int length)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789"
                           "+/";
    int charset_size = sizeof(charset) - 1;

    for (int i = 0; i < length; i++) {
        int key = random() % charset_size;
        buffer[i] = charset[key];
    }
    buffer[length] = '\0';
}
