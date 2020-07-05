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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE == 0)
#define _POSIX_C_SOURCE 1
#endif
#include <limits.h>

#include "rtpp_codeptr.h"
#include "rtpp_glitch.h"
#include "rtpp_autoglitch.h"
#include "libexecinfo/execinfo.h"

#undef pthread_create

int
rtpp_glitch_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
  void *(*start_routine)(void *), void *arg, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (pthread_create(thread, attr, start_routine, arg));
glitched:
    errno = EFAULT;
    return (-1);
}

#undef pthread_mutex_init

int
rtpp_glitch_pthread_mutex_init(pthread_mutex_t *mutex,
  const pthread_mutexattr_t *attr, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (pthread_mutex_init(mutex, attr));
glitched:
    return (ENOMEM);
}

#undef socket

int
rtpp_glitch_socket(int domain, int type, int protocol, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(socket(domain, type, protocol));
glitched:
    errno = ENFILE;
    return (-1);
}

#undef listen

int
rtpp_glitch_listen(int s, int backlog, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(listen(s, backlog));
glitched:
    errno = EOPNOTSUPP;
    return (-1);
}

#undef bind

int
rtpp_glitch_bind(int s, const struct sockaddr *addr, socklen_t addrlen,
  HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(bind(s, addr, addrlen));
glitched:
    errno = EADDRINUSE;
    return (-1);
}

#undef accept

int
rtpp_glitch_accept(int s, struct sockaddr *addr, socklen_t *addrlen,
  HERETYPEARG)
{
    int fdc;

    GLITCH_INJECT(HEREARG, glitched);
    return(accept(s, addr, addrlen));
glitched:
    fdc = accept(s, addr, addrlen);
    if (fdc < 0)
         return (-1);
    close(fdc);
    errno = ECONNABORTED;
    return (-1);
}

#undef send

ssize_t
rtpp_glitch_send(int s, const void *msg, size_t len, int flags,
  HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (send(s, msg, len, flags));
glitched:
    shutdown(s, SHUT_WR);
    errno = EHOSTDOWN;
    return (-1);
}

#undef connect

int
rtpp_glitch_connect(int s, const struct sockaddr *name, socklen_t namelen,
  HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (connect(s, name, namelen));
glitched:
    errno = ETIMEDOUT;
    return (-1);
}

#undef chmod

int
rtpp_glitch_chmod(const char *path, mode_t mode, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(chmod(path, mode));
glitched:
    errno = EIO;
    return (-1);
}

#undef fstat

int
rtpp_glitch_fstat(int fd, struct stat *sb, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(fstat(fd, sb));
glitched:
    errno = EIO;
    return (-1);
}

#undef stat

int
rtpp_glitch_stat(const char *path, struct stat *sb, HERETYPEARG)
{
    struct stat tsb;

    GLITCH_INJECT(HEREARG, glitched);
    return(stat(path, sb));
glitched:
    errno = (stat(path, &tsb) == 0) ? ENOENT : EIO;
    return (-1);
}

#undef getaddrinfo

int
rtpp_glitch_getaddrinfo(const char *hostname, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return(getaddrinfo(hostname, servname, hints, res));
glitched:
    return (EAI_MEMORY);
}

#undef open

#include <stdarg.h>

int
rtpp_glitch_open(const char *path, int flags, HERETYPEARG, ...)
{

    GLITCH_INJECT_IF(HEREARG, glitched,
      (strcmp(path, "/dev/urandom") != 0 && strcmp(mlp->funcn, "main") != 0 &&
      strcmp(mlp->funcn, "rtpp_get_sched_hz_linux") != 0));

    if ((flags & O_CREAT) != 0) {
        va_list ap;
        int mode;

        va_start(ap, HEREARG);
        mode = va_arg(ap, int);
        va_end(ap);
        return(open(path, flags, mode));
    }
    return(open(path, flags));
glitched:
    errno = EACCES;
    return (-1);
}

#undef fcntl

int
rtpp_glitch_fcntl(int fd, int cmd, HERETYPEARG, ...)
{
    va_list args;
    long arg;

    GLITCH_INJECT(HEREARG, glitched);
    va_start(args, HEREARG);
    arg = va_arg(args, long);
    va_end(args);
    return(fcntl(fd, cmd, arg));
glitched:
    errno = EINVAL;
    return (-1);
}

#undef getrlimit

struct rlimit;

int
rtpp_glitch_getrlimit(int resource, struct rlimit *rlp, HERETYPEARG)
{
    GLITCH_INJECT(HEREARG, glitched);
    return (getrlimit(resource, rlp));
glitched:
    errno = EFAULT;
    return (-1);
}

#undef setrlimit

int
rtpp_glitch_setrlimit(int resource, struct rlimit *rlp, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (setrlimit(resource, rlp));
glitched:
    errno = EPERM;
    return (-1);
}

#undef dup2

int
rtpp_glitch_dup2(int oldd, int newd, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (dup2(oldd, newd));
glitched:
    errno = EMFILE;
    return (-1);
}

#undef setuid

int
rtpp_glitch_setuid(uid_t uid, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (setuid(uid));
glitched:
    errno = EPERM;
    return (-1);
}

#undef setgid

int
rtpp_glitch_setgid(gid_t gid, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (setgid(gid));
glitched:
    errno = EPERM;
    return (-1);
}

#undef pipe

int
rtpp_glitch_pipe(int fildes[2], HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (pipe(fildes));
glitched:
    errno = ENOMEM;
    return (-1);
}

#undef write

ssize_t
rtpp_glitch_write(int fd, const void *buf, size_t nbytes, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (write(fd, buf, nbytes));
glitched:
    errno = EDQUOT;
    return (-1);
}

#undef setsid

pid_t
rtpp_glitch_setsid(HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (setsid());
glitched:
    errno = EPERM;
    return (-1);
}

#undef fork

pid_t
rtpp_glitch_fork(HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (fork());
glitched:
    errno = ENOMEM;
    return (-1);
}

#undef realpath

char *
rtpp_glitch_realpath(const char *pathname, char *resolved_path, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (realpath(pathname, resolved_path));
glitched:
    errno = ENOMEM;
    if (resolved_path != NULL) {
        strncpy(resolved_path, pathname, PATH_MAX - 1);
        resolved_path[PATH_MAX - 1] = '\0';
        errno = EIO;
    }
    return (NULL);
}

#undef mmap

void *
rtpp_glitch_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset, HERETYPEARG)
{

    GLITCH_INJECT(HEREARG, glitched);
    return (mmap(addr, len, prot, flags, fd, offset));
glitched:
    errno = ENOMEM;
    return (MAP_FAILED);
}

#include <dlfcn.h>

#undef dlopen

static const char *dlerp;

void *
rtpp_glitch_dlopen(const char *path, int mode, HERETYPEARG)
{
    GLITCH_INJECT(HEREARG, glitched);
    dlerp = NULL;
    return (dlopen(path, mode));
glitched:
    dlerp = "foo bar baz";
    return (NULL);
}

#undef dlerror

const char *
rtpp_glitch_dlerror(HERETYPEARG)
{
    const char *rval;

    rval = (dlerp != NULL) ? dlerp : dlerror();
    if (dlerp != NULL) {
        dlerp = NULL;
    }
    return (rval);
}

#undef dlsym

void *
rtpp_glitch_dlsym(void *handle, const char *symbol, HERETYPEARG)
{
    GLITCH_INJECT(HEREARG, glitched);
    dlerp = NULL;
    return (dlsym(handle, symbol));
glitched:
    dlerp = "baz foo bar";
    return (NULL);
}

#include <stdio.h>

#undef fwrite

size_t
rtpp_glitch_fwrite(const void *ptr, size_t size, size_t nmemb,
  FILE *stream, HERETYPEARG)
{
    size_t rv = 0;

    GLITCH_INJECT(HEREARG, glitched);
    return (fwrite(ptr, size, nmemb, stream));
glitched:
    if (nmemb > 1) {
        rv = fwrite(ptr, size, nmemb - 1, stream);
    }
    return (rv);
}
