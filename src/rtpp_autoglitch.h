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

int rtpp_glitch_pthread_create(pthread_t *, const pthread_attr_t *,
  void *(*)(void *), void *, const char *, int, const char *);

#ifdef pthread_create
# undef pthread_create
#endif

#define pthread_create(thread, attr, start_routine, arg) \
  rtpp_glitch_pthread_create(thread, attr, start_routine, arg, \
  __FILE__, __LINE__, __func__)

int rtpp_glitch_pthread_mutex_init(pthread_mutex_t *,
  const pthread_mutexattr_t *, const char *, int, const char *);

#ifdef pthread_mutex_init
# undef pthread_mutex_init
#endif

#define pthread_mutex_init(mutex, attr) \
  rtpp_glitch_pthread_mutex_init(mutex, attr, __FILE__, __LINE__, __func__)

#include <sys/socket.h>

int rtpp_glitch_socket(int, int, int, const char *, int, const char *);

#ifdef socket
# undef socket
#endif

#define socket(domain, type, protocol) \
  rtpp_glitch_socket(domain, type, protocol, __FILE__, __LINE__, __func__)

#endif /* _RTPP_AUTOGLITCH_H */
