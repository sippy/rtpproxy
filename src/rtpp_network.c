/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2009 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#endif

#include "rtpp_types.h"
#include "rtpp_network.h"
#include "rtpp_debug.h"
#include "rtpp_util.h"

int
ishostseq(const struct sockaddr *ia1, const struct sockaddr *ia2)
{

    if (ia1->sa_family != ia2->sa_family)
	return 0;

    switch (ia1->sa_family) {
    case AF_INET:
	return (satosin(ia1)->sin_addr.s_addr ==
	  satosin(ia2)->sin_addr.s_addr);

    case AF_INET6:
	return (memcmp(&satosin6(ia1)->sin6_addr.s6_addr[0],
	  &satosin6(ia2)->sin6_addr.s6_addr[0],
	  sizeof(struct in6_addr)) == 0);

    default:
	break;
    }
    /* Can't happen */
    abort();
}

int
ishostnull(const struct sockaddr *ia)
{
    struct in6_addr *ap;

    switch (ia->sa_family) {
    case AF_INET:
	return (satosin(ia)->sin_addr.s_addr == INADDR_ANY);

    case AF_INET6:
	ap = &satosin6(ia)->sin6_addr;
	return ((*(const uint32_t *)(const void *)(&ap->s6_addr[0]) == 0) &&
		(*(const uint32_t *)(const void *)(&ap->s6_addr[4]) == 0) &&
		(*(const uint32_t *)(const void *)(&ap->s6_addr[8]) == 0) &&
		(*(const uint32_t *)(const void *)(&ap->s6_addr[12]) == 0));

    default:
	break;
    }

    abort();
}

uint16_t
getport(const struct sockaddr *ia)
{

    return (ntohs(getnport(ia)));
}

uint16_t
getnport(const struct sockaddr *ia)
{

    switch (ia->sa_family) {
    case AF_INET:
        return (satosin(ia)->sin_port);

    case AF_INET6:
        return (satosin6(ia)->sin6_port);

    default:
        break;
    }
    /* Can't happen */
    abort();
}

int
isaddrseq(const struct sockaddr *ia1, const struct sockaddr *ia2)
{

    if (ishostseq(ia1, ia2) == 0)
        return (0);
    return (getport(ia1) == getport(ia2));
}

void
setport(struct sockaddr *ia, int portnum)
{

    assert(IS_VALID_PORT(portnum));

    switch (ia->sa_family) {
    case AF_INET:
        satosin(ia)->sin_port = htons(portnum);
        return;

    case AF_INET6:
        satosin6(ia)->sin6_port = htons(portnum);
        return;

    default:
        break;
    }
    /* Can't happen */
    abort();
}

void
setanyport(struct sockaddr *ia)
{

    switch (ia->sa_family) {
    case AF_INET:
        satosin(ia)->sin_port = 0;
        return;

    case AF_INET6:
        satosin6(ia)->sin6_port = 0;
        return;

    default:
        break;
    }
    /* Can't happen */
    abort();
}

char *
addr2char_r(const struct sockaddr *ia, char *buf, int size)
{
    void *addr;

    switch (ia->sa_family) {
    case AF_INET:
	addr = &(satosin(ia)->sin_addr);
	break;

    case AF_INET6:
	addr = &(satosin6(ia)->sin6_addr);
	break;

    default:
	abort();
    }

    return (char *)((void *)inet_ntop(ia->sa_family, addr, buf, size));
}

char *
addrport2char_r(const struct sockaddr *ia, char *buf, int size, char portsep)
{
    char abuf[MAX_ADDR_STRLEN];
    const char *bs, *es;

    switch (ia->sa_family) {
    case AF_INET:
        bs = es = "";
        break;

    case AF_INET6:
        bs = "[";
        es = "]";
        break;

    default:
        abort();
    }

    if (addr2char_r(ia, abuf, MAX_ADDR_STRLEN) == NULL)
        return (NULL);
    snprintf(buf, size, "%s%s%s%c%u", bs, abuf, es, portsep, getport(ia));
    return (buf);
}

int
resolve(struct sockaddr *ia, int pf, const char *host,
  const char *servname, int flags)
{
    int n;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = flags;	     /* We create listening sockets */
    hints.ai_family = pf;	       /* Protocol family */
    hints.ai_socktype = SOCK_DGRAM;     /* UDP */

    n = getaddrinfo(host, servname, &hints, &res);
    if (n == 0) {
	RTPP_DBG_ASSERT(res->ai_family == pf);
	/* Use the first socket address returned */
	memcpy(ia, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
        return 0;
    }
    if ((flags & AI_NUMERICHOST) == 0)
        return n;
    void *dst = (pf == AF_INET) ? (void *)&(satosin(ia)->sin_addr) :
      (void *)&(satosin6(ia)->sin6_addr);
    if (inet_pton(pf, host, dst) != 1)
        return n;
    int port = 0;
    if (servname != NULL) {
        if (atoi_saferange(servname, &port, 1, 65535) != ATOI_OK)
            return n;
    }
    ia->sa_family = pf;
    setport(ia, port);
    return 0;
}

#if !defined(BYTE_ORDER)
# error "BYTE_ORDER needs to be defined"
#endif

/*
 * Checksum routine for Internet Protocol family headers.
 */
uint16_t
rtpp_in_cksum(void *p, int len)
{
    int sum = 0, oddbyte = 0, v = 0;
    u_char *cp = p;

    /* we assume < 2^16 bytes being summed */
    while (len > 0) {
        if (oddbyte) {
            sum += v + *cp++;
            len--;
        }
        if (((long)cp & 1) == 0) {
            while ((len -= 2) >= 0) {
                sum += *(u_short *)cp;
                cp += 2;
            }
        } else {
            while ((len -= 2) >= 0) {
#if BYTE_ORDER == BIG_ENDIAN
                sum += *cp++ << 8;
                sum += *cp++;
#else
                sum += *cp++;
                sum += *cp++ << 8;
#endif
            }
        }
        if ((oddbyte = len & 1) != 0) {
#if BYTE_ORDER == BIG_ENDIAN
            v = *cp << 8;
#else
            v = *cp;
#endif
        }
    }
    if (oddbyte)
        sum += v;
    sum = (sum >> 16) + (sum & 0xffff); /* add in accumulated carries */
    sum += sum >> 16;               /* add potential last carry */
    return (0xffff & ~sum);
}

int
local4remote(const struct sockaddr *ra, struct sockaddr_storage *la)
{
    int s, r;
    socklen_t llen;

    s = socket(ra->sa_family, SOCK_DGRAM, 0);
    if (s == -1) {
        return (-1);
    }
    if (connect(s, ra, SA_LEN(ra)) == -1) {
        close(s);
        return (-1);
    }
    llen = sizeof(*la);
    r = getsockname(s, sstosa(la), &llen);
    close(s);
    return (r);
}

int
extractaddr(const char *str, const char **begin, const char **end, int *pf)
{
    const char *t;
    int tpf;

    if (*str != '[') {
	tpf = AF_INET;
	for (t = str; *str != '\0'; str++) {
	    if (!isdigit(*str) && *str != '.')
		break;
	}
    } else {
	tpf = AF_INET6;
	str++;
	for (t = str; *str != '\0'; str++) {
	    if (!isxdigit(*str) && *str != ':')
		break;
	}
	if (*str != ']')
	    return (-1);
    }
    if (t == str)
	return (-1);
    if (tpf == AF_INET6)
	*end = (char *)(str + 1);
    else
	*end = (char *)str;
    *pf = tpf;
    *begin = (char *)t;
    return(str - t);
}

int
is_wildcard(const char *hostnm, int pf)
{

    if (strcmp(hostnm, "*") == 0)
        return 1;
    if ((pf == AF_INET) && (strcmp(hostnm, "0.0.0.0") == 0))
        return 1;
    if ((pf == AF_INET6) && (strcmp(hostnm, "::") == 0))
        return 1;
    return 0;
}

int
is_numhost(const char *hostnm, int pf)
{
    const char *numset = (pf == AF_INET) ? "0123456789." :
                                           "0123456789abcdefABCDEF:";
    if (strspn(hostnm, numset) == strlen(hostnm))
        return 1;
    return 0;
}

int
setbindhost(struct sockaddr *ia, int pf, const char *bindhost,
  const char *servname, int no_resolve)
{
    int n;
    int rmode = AI_PASSIVE;

    /*
     * If user specified * then change it to NULL,
     * that will make getaddrinfo to return addr_any socket
     */
    if (bindhost && is_wildcard(bindhost, pf))
	bindhost = NULL;

    if (bindhost != NULL) {
        if (no_resolve || is_numhost(bindhost, pf)) {
            rmode |= AI_NUMERICHOST;
        }
        rmode |= AI_ADDRCONFIG;
    }

    if ((n = resolve(ia, pf, bindhost, servname, rmode)) != 0) {
	warnx("setbindhost: %s for %s %s", gai_strerror(n), bindhost, servname);
	return -1;
    }
    return 0;
}
