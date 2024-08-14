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

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_network.h"
#include "rtpp_network_io.h"

static ssize_t
_recvfromto(int s, void *buf, size_t len, struct sockaddr *from,
  socklen_t *fromlen, struct sockaddr *to, socklen_t *tolen,
  void *tp, size_t tplen, int mtype)
{
    /* We use a union to make sure hdr is aligned */
    union {
        struct cmsghdr hdr;
        unsigned char buf[CMSG_SPACE(1024)];
    } cmsgbuf;
#if !defined(IP_RECVDSTADDR)
    struct in_pktinfo *pktinfo;
#endif
    struct cmsghdr *cmsg;
    struct msghdr msg;
    struct iovec iov;
    ssize_t rval;

    memset(&msg, '\0', sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = len;
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    rval = recvmsg(s, &msg, 0);
    if (rval < 0)
        return (rval);

    *tolen = 0;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
      cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#if defined(IP_RECVDSTADDR)
        if (cmsg->cmsg_level == IPPROTO_IP &&
          cmsg->cmsg_type == IP_RECVDSTADDR) {
            memcpy(&satosin(to)->sin_addr, CMSG_DATA(cmsg),
              sizeof(struct in_addr));
            to->sa_family = AF_INET;
            *tolen = sizeof(struct sockaddr_in);
            break;
        }
#else
        if (cmsg->cmsg_level == SOL_IP &&
          cmsg->cmsg_type == IP_PKTINFO) {
            pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
            memcpy(&satosin(to)->sin_addr, &pktinfo->ipi_addr,
              sizeof(struct in_addr));
            to->sa_family = AF_INET;
            *tolen = sizeof(struct sockaddr_in);
            break;
        }
#endif
        if ((cmsg->cmsg_level == SOL_SOCKET) &&
          (cmsg->cmsg_type == mtype)) {
            memcpy(tp, CMSG_DATA(cmsg), tplen);
        }
    }
    *fromlen = msg.msg_namelen;
    return (rval);
}

ssize_t
recvfromto(int s, void *buf, size_t len, struct sockaddr *from,
  socklen_t *fromlen, struct sockaddr *to, socklen_t *tolen,
  struct timespec *timeptr)
{
    ssize_t r;
    struct timeval rtime = {0};

    r = _recvfromto(s, buf, len, from, fromlen, to, tolen, &rtime,
      sizeof(rtime), SCM_TIMESTAMP);
    if (r >= 0) {
        timeptr->tv_sec = rtime.tv_sec;
        timeptr->tv_nsec = rtime.tv_usec * 1000;
    }
    return (r);
}

#if HAVE_SO_TS_CLOCK
ssize_t
recvfromto_mono(int s, void *buf, size_t len, struct sockaddr *from,
  socklen_t *fromlen, struct sockaddr *to, socklen_t *tolen,
  struct timespec *timeptr)
{

    return (_recvfromto(s, buf, len, from, fromlen, to, tolen, timeptr,
      sizeof(*timeptr), SCM_MONOTONIC));
}
#endif /* HAVE_SO_TS_CLOCK */
