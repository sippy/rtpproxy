/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_AUTOGLITCH_H
#define _RTPP_AUTOGLITCH_H

#define LOCTYPES const char *, int, const char *
#define LOCVALS  __FILE__, __LINE__, __func__

int rtpp_glitch_pthread_create(pthread_t *, const pthread_attr_t *,
  void *(*)(void *), void *, LOCTYPES);

#ifdef pthread_create
# undef pthread_create
#endif

#define pthread_create(thread, attr, start_routine, arg) \
  rtpp_glitch_pthread_create(thread, attr, start_routine, arg, LOCVALS)

int rtpp_glitch_pthread_mutex_init(pthread_mutex_t *,
  const pthread_mutexattr_t *, LOCTYPES);

#ifdef pthread_mutex_init
# undef pthread_mutex_init
#endif

#define pthread_mutex_init(mutex, attr) \
  rtpp_glitch_pthread_mutex_init(mutex, attr, LOCVALS)

#include <sys/socket.h>

int rtpp_glitch_socket(int, int, int, LOCTYPES);

#ifdef socket
# undef socket
#endif

#define socket(domain, type, protocol) \
  rtpp_glitch_socket(domain, type, protocol, LOCVALS)

int rtpp_glitch_listen(int, int, LOCTYPES);

#ifdef listen
# undef listen
#endif

#define listen(s, backlog) rtpp_glitch_listen(s, backlog, LOCVALS)

int rtpp_glitch_bind(int, const struct sockaddr *, socklen_t, LOCTYPES);

#ifdef bind
# undef bind
#endif

#define bind(s, addr, addrlen) rtpp_glitch_bind(s, addr, addrlen, LOCVALS)

int rtpp_glitch_accept(int, struct sockaddr * restrict, socklen_t * restrict,
  LOCTYPES);

#ifdef accept
# undef accept
#endif

#define accept(s, addr, addrlen) rtpp_glitch_accept(s, addr, addrlen, LOCVALS)

#include <sys/stat.h>

int rtpp_glitch_chmod(const char *path, mode_t mode, LOCTYPES);

#ifdef chmod
# undef chmod
#endif

#define chmod(path, mode) rtpp_glitch_chmod(path, mode, LOCVALS)

#include <netdb.h>

int rtpp_glitch_getaddrinfo(const char *, const char *, const struct addrinfo *,
  struct addrinfo **, LOCTYPES);

#ifdef getaddrinfo
# undef getaddrinfo
#endif

#define getaddrinfo(hostname, servname, hints, res) \
  rtpp_glitch_getaddrinfo(hostname, servname, hints, res, LOCVALS)

#include <fcntl.h>

int rtpp_glitch_open(const char *, int, LOCTYPES, ...);

#ifdef open
# undef open
#endif

#define open(path, flags, args...) rtpp_glitch_open(path, flags, LOCVALS, ## args)

int rtpp_glitch_fcntl(int, int, LOCTYPES, ...);

#ifdef fcntl
# undef fcntl
#endif

#define fcntl(fd, cmd, args...) rtpp_glitch_fcntl(fd, cmd, LOCVALS, ## args)

#endif /* _RTPP_AUTOGLITCH_H */
