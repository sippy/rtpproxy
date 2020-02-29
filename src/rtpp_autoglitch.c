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
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>

#include "rtpp_codeptr.h"
#include "rtpp_glitch.h"
#include "rtpp_autoglitch.h"
#include "libexecinfo/execinfo.h"

#undef pthread_create

#define LOCTYPEVALS LOCTYPES mlp

int
rtpp_glitch_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
  void *(*start_routine)(void *), void *arg, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (pthread_create(thread, attr, start_routine, arg));
glitched:
    errno = EFAULT;
    return (-1);
}

#undef pthread_mutex_init

int
rtpp_glitch_pthread_mutex_init(pthread_mutex_t *mutex,
  const pthread_mutexattr_t *attr, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (pthread_mutex_init(mutex, attr));
glitched:
    return (ENOMEM);
}

#undef socket

int
rtpp_glitch_socket(int domain, int type, int protocol, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return(socket(domain, type, protocol));
glitched:
    errno = ENFILE;
    return (-1);
}

#undef listen

int
rtpp_glitch_listen(int s, int backlog, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return(listen(s, backlog));
glitched:
    errno = EOPNOTSUPP;
    return (-1);
}

#undef bind

int
rtpp_glitch_bind(int s, const struct sockaddr *addr, socklen_t addrlen,
  LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return(bind(s, addr, addrlen));
glitched:
    errno = EADDRINUSE;
    return (-1);
}

#undef accept

int
rtpp_glitch_accept(int s, struct sockaddr * restrict addr,
  socklen_t * restrict addrlen, LOCTYPEVALS)
{
    int fdc;

    GLITCH_INJECT(mlp, glitched);
    return(accept(s, addr, addrlen));
glitched:
    fdc = accept(s, addr, addrlen);
    if (fdc < 0)
         return (-1);
    close(fdc);
    errno = ECONNABORTED;
    return (-1);
}

#undef chmod

int
rtpp_glitch_chmod(const char *path, mode_t mode, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return(chmod(path, mode));
glitched:
    errno = EIO;
    return (-1);
}

#undef getaddrinfo

int
rtpp_glitch_getaddrinfo(const char *hostname, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return(getaddrinfo(hostname, servname, hints, res));
glitched:
    return (EAI_MEMORY);
}

#undef open

#include <stdarg.h>

int
rtpp_glitch_open(const char *path, int flags, LOCTYPEVALS, ...)
{

    if (strcmp(path, "/dev/urandom") != 0 && strcmp(mlp->funcn, "main") != 0 &&
      strcmp(mlp->funcn, "rtpp_get_sched_hz_linux") != 0) {
        GLITCH_INJECT(mlp, glitched);
    }

    if ((flags & O_CREAT) != 0) {
        va_list ap;
        int mode;

        va_start(ap, mlp);
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
rtpp_glitch_fcntl(int fd, int cmd, LOCTYPEVALS, ...)
{
    va_list args;
    long arg;

    GLITCH_INJECT(mlp, glitched);
    va_start(args, mlp);
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
rtpp_glitch_getrlimit(int resource, struct rlimit *rlp, LOCTYPEVALS)
{
    GLITCH_INJECT(mlp, glitched);
    return (getrlimit(resource, rlp));
glitched:
    errno = EFAULT;
    return (-1);
}

#undef setrlimit

int
rtpp_glitch_setrlimit(int resource, struct rlimit *rlp, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (setrlimit(resource, rlp));
glitched:
    errno = EPERM;
    return (-1);
}

#undef dup2

int
rtpp_glitch_dup2(int oldd, int newd, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (dup2(oldd, newd));
glitched:
    errno = EMFILE;
    return (-1);
}

#undef setuid

int
rtpp_glitch_setuid(uid_t uid, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (setuid(uid));
glitched:
    errno = EPERM;
    return (-1);
}

#undef setgid

int
rtpp_glitch_setgid(gid_t gid, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (setgid(gid));
glitched:
    errno = EPERM;
    return (-1);
}

#undef pipe

int
rtpp_glitch_pipe(int fildes[2], LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (pipe(fildes));
glitched:
    errno = ENOMEM;
    return (-1);
}

#undef write

ssize_t
rtpp_glitch_write(int fd, const void *buf, size_t nbytes, LOCTYPEVALS)
{

    GLITCH_INJECT(mlp, glitched);
    return (write(fd, buf, nbytes));
glitched:
    errno = EDQUOT;
    return (-1);
}
