/*
 * Copyright (c) 2022 Sippy Software, Inc., http://www.sippysoft.com
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

#include "config.h"

#if HAVE_KQUEUE
#include <sys/types.h>
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rtpp_epoll.h"
#include "rtpp_debug.h"

int
rtpp_epoll_create()
{
#if HAVE_KQUEUE
    int qid = kqueue();

    return (qid);
#else
    return (epoll_create(1));
#endif
}

int
rtpp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
#if HAVE_KQUEUE
    struct kevent k_event;
    void *udata;

    if (op == EPOLL_CTL_DEL) {
        EV_SET(&k_event, fd, EVFILT_READ, op, 0, 0, NULL);
        int r1 = kevent(epfd, &k_event, 1, NULL, 0, NULL);
#if 0
        EV_SET(&k_event, fd, EVFILT_WRITE, op, 0, 0, NULL);
        int r2 = kevent(epfd, &k_event, 1, NULL, 0, NULL);
        return (r1 == 0 || r2 == 0) ? 0 : -1;
#endif
        return (r1);
    }

    udata = event->data.ptr;
    if (event->events & EPOLLIN) {
        EV_SET(&k_event, fd, EVFILT_READ, op, 0, 0, udata);
        if (kevent(epfd, &k_event, 1, NULL, 0, NULL) != 0)
            return (-1);
        return (0);
    }
#if 0
    if (event->events & EPOLLOUT) {
        EV_SET(&k_event, fd, EVFILT_WRITE, op, 0, 0, udata);
        if (kevent(epfd, &k_event, 1, NULL, 0, NULL) != 0)
            return (-1);
    }
#endif
    return (-1);
#else
    return (epoll_ctl(epfd, op, fd, event));
#endif
}

#if HAVE_KQUEUE
static int
append_kevent(struct epoll_event *events, int alloclen, const struct kevent *kep, int i)
{
    int j;

    for (j = 0; j < alloclen; j++) {
        if (kep[j].ident == kep[i].ident)
            break;
    }
    if (j == alloclen) {
        memset(&events[j], '\0', sizeof(events[j]));
        events[j].data.ptr = kep[i].udata;
    } else {
        RTPP_DBG_ASSERT(events[j].data.ptr == kep[i].udata);
    }
    switch (kep[i].filter) {
    case EVFILT_READ:
        events[j].events |= EPOLLIN;
        break;

#if 0
    case EVFILT_WRITE:
        events[j].events |= EPOLLOUT;
        break;
#endif

    default:
        abort();
    }
    return (j < alloclen ? alloclen : alloclen + 1);
}
#endif

int
rtpp_epoll_wait(int epfd, struct epoll_event *events,
  int maxevents, int timeout)
{
#if HAVE_KQUEUE
    struct kevent *kep;
    struct timespec tot, *top;
    int ret, kret;

    kep = alloca(sizeof(struct kevent) * maxevents);
    if (kep == NULL)
        return (-1);
    if (timeout >= 0) {
        tot.tv_sec = timeout / 1000;
        tot.tv_nsec = (timeout % 1000) * 1000000;
        top = &tot;
    } else {
        top = NULL;
    }
    kret = kevent(epfd, NULL, 0, kep, maxevents, top);
    if (kret <= 0)
        return (kret);
    ret = 0;
    for (int i = 0; i < kret; i++) {
        ret = append_kevent(events, ret, kep, i);
    }
    return (ret);
#else
    return (epoll_wait(epfd, events, maxevents, timeout));
#endif
}
