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

#include "rtpp_codeptr.h"

int rtpp_glitch_pthread_create(pthread_t *, const pthread_attr_t *,
  void *(*)(void *), void *, HERETYPE);

#ifdef pthread_create
# undef pthread_create
#endif

#define pthread_create(thread, attr, start_routine, arg) \
  rtpp_glitch_pthread_create(thread, attr, start_routine, arg, HEREVAL)

int rtpp_glitch_pthread_mutex_init(pthread_mutex_t *,
  const pthread_mutexattr_t *, HERETYPE) RTPP_EXPORT;

#ifdef pthread_mutex_init
# undef pthread_mutex_init
#endif

#define pthread_mutex_init(mutex, attr) \
  rtpp_glitch_pthread_mutex_init(mutex, attr, HEREVAL)

#include <sys/socket.h>

int rtpp_glitch_socket(int, int, int, HERETYPE) RTPP_EXPORT;

#ifdef socket
# undef socket
#endif

#define socket(domain, type, protocol) \
  rtpp_glitch_socket(domain, type, protocol, HEREVAL)

int rtpp_glitch_listen(int, int, HERETYPE);

#ifdef listen
# undef listen
#endif

#define listen(s, backlog) rtpp_glitch_listen(s, backlog, HEREVAL)

int rtpp_glitch_bind(int, const struct sockaddr *, socklen_t, HERETYPE);

#ifdef bind
# undef bind
#endif

#define bind(s, addr, addrlen) rtpp_glitch_bind(s, addr, addrlen, HEREVAL)

int rtpp_glitch_accept(int, struct sockaddr *, socklen_t *, HERETYPE);

#ifdef accept
# undef accept
#endif

#define accept(s, addr, addrlen) rtpp_glitch_accept(s, addr, addrlen, HEREVAL)

ssize_t rtpp_glitch_send(int s, const void *msg, size_t len, int flags, HERETYPE)
  RTPP_EXPORT;

#ifdef send
# undef send
#endif

#define send(s, msg, len, flags) rtpp_glitch_send(s, msg, len, flags, HEREVAL)

int rtpp_glitch_connect(int s, const struct sockaddr *name, socklen_t namelen, HERETYPE)
  RTPP_EXPORT;

#ifdef connect
# undef connect
#endif

#define connect(s, name, namelen) rtpp_glitch_connect(s, name, namelen, HEREVAL)

#include <sys/stat.h>

int rtpp_glitch_chmod(const char *path, mode_t mode, HERETYPE);

#ifdef chmod
# undef chmod
#endif

#define chmod(path, mode) rtpp_glitch_chmod(path, mode, HEREVAL)

int rtpp_glitch_fstat(int fd, struct stat *sb, HERETYPE)
  RTPP_EXPORT;

#ifdef fstat
# undef fstat
#endif

#define fstat(fd, sb) rtpp_glitch_fstat(fd, sb, HEREVAL)

int rtpp_glitch_stat(const char *path, struct stat *sb, HERETYPE)
  RTPP_EXPORT;

#ifdef stat
# undef stat
#endif

#define stat(path, sb) rtpp_glitch_stat(path, sb, HEREVAL)

#include <netdb.h>

int rtpp_glitch_getaddrinfo(const char *, const char *, const struct addrinfo *,
  struct addrinfo **, HERETYPE) RTPP_EXPORT;

#ifdef getaddrinfo
# undef getaddrinfo
#endif

#define getaddrinfo(hostname, servname, hints, res) \
  rtpp_glitch_getaddrinfo(hostname, servname, hints, res, HEREVAL)

#include <fcntl.h>

int rtpp_glitch_open(const char *, int, HERETYPE, ...)
   RTPP_EXPORT;

#ifdef open
# undef open
#endif

#define open(path, flags, args...) rtpp_glitch_open(path, flags, HEREVAL, ## args)

int rtpp_glitch_fcntl(int, int, HERETYPE, ...) RTPP_EXPORT;

#ifdef fcntl
# undef fcntl
#endif

#define fcntl(fd, cmd, args...) rtpp_glitch_fcntl(fd, cmd, HEREVAL, ## args)

struct rlimit;

#include <sys/resource.h>

int rtpp_glitch_getrlimit(int, struct rlimit *, HERETYPE);

#ifdef getrlimit
# undef getrlimit
#endif

#define getrlimit(resource, rlp) rtpp_glitch_getrlimit(resource, rlp, HEREVAL)

int rtpp_glitch_setrlimit(int, struct rlimit *, HERETYPE);

#ifdef setrlimit
# undef setrlimit
#endif

#define setrlimit(resource, rlp) rtpp_glitch_setrlimit(resource, rlp, HEREVAL)

#include <unistd.h>

int rtpp_glitch_dup2(int, int, HERETYPE);

#ifdef dup2
# undef dup2
#endif

#define dup2(oldd, newd) rtpp_glitch_dup2(oldd, newd, HEREVAL)

int rtpp_glitch_setuid(uid_t, HERETYPE);

#ifdef setuid
# undef setuid
#endif

#define setuid(uid) rtpp_glitch_setuid(uid, HEREVAL)

int rtpp_glitch_setgid(gid_t, HERETYPE);

#ifdef setgid
# undef setgid
#endif

#define setgid(gid) rtpp_glitch_setgid(gid, HEREVAL)

int rtpp_glitch_pipe(int [2], HERETYPE);

#ifdef pipe
# undef pipe
#endif

#define pipe(fildes) rtpp_glitch_pipe(fildes, HEREVAL)

ssize_t rtpp_glitch_write(int, const void *, size_t, HERETYPE)
  RTPP_EXPORT;

#ifdef write
# undef write
#endif

#define write(fd, buf, nbytes) rtpp_glitch_write(fd, buf, nbytes, HEREVAL)

pid_t rtpp_glitch_setsid(HERETYPE);

#ifdef setsid
# undef setsid
#endif

#define setsid() rtpp_glitch_setsid(HEREVAL)

pid_t rtpp_glitch_fork(HERETYPE);

#ifdef fork
# undef fork
#endif

#define fork() rtpp_glitch_fork(HEREVAL)

#include <stdlib.h>

char *rtpp_glitch_realpath(const char *, char *, HERETYPE);

#ifdef realpath
# undef realpath
#endif

#define realpath(pathname, resolved_path) rtpp_glitch_realpath(pathname, resolved_path, HEREVAL)

#include <sys/mman.h>

void *rtpp_glitch_mmap(void *, size_t, int, int, int, off_t, HERETYPE);

#ifdef mmap
# undef mmap
#endif

#define mmap(addr, len, prot, flags, fd, offset) rtpp_glitch_mmap(addr, len, prot, flags, fd, offset, HEREVAL)

#include <dlfcn.h>

void *rtpp_glitch_dlopen(const char *path, int mode, HERETYPE);

#ifdef dlopen
# undef dlopen
#endif

#define dlopen(path, mode) rtpp_glitch_dlopen(path, mode, HEREVAL)

const char *rtpp_glitch_dlerror(HERETYPE);

#ifdef dlerror
# undef dlerror
#endif

#define dlerror() rtpp_glitch_dlerror(HEREVAL)

void *rtpp_glitch_dlsym(void *handle, const char *symbol, HERETYPE);

#ifdef dlsym
# undef dlsym
#endif

#define dlsym(handle, symbol) rtpp_glitch_dlsym(handle, symbol, HEREVAL)

#include <stdio.h>

size_t rtpp_glitch_fwrite(const void *ptr, size_t size, size_t nmemb,
  FILE *stream, HERETYPE) RTPP_EXPORT;

#ifdef fwrite
# undef fwrite
#endif

#define fwrite(ptr, size, nmemb, stream) \
  rtpp_glitch_fwrite(ptr, size, nmemb, stream, HEREVAL)

#endif /* _RTPP_AUTOGLITCH_H */
