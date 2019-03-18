/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "libexecinfo/execinfo.h"

void
rtpp_stacktrace(int sig)
{
    /* Obtain a backtrace and print it to stderr. */
    void *array[10];
    size_t size;
    char **strings;
    int i;

    size = backtrace(array, 10);
    strings = backtrace_symbols(array, size);

    fprintf(stderr, "Died on signal %d, obtained %lu stack frames.\n",
      sig, (unsigned long)size);

    for (i = 0; i < size; i++)
        fprintf(stderr, "%s\n", strings[i]);
    fflush(stderr);
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

void
rtpp_stacktrace_print(const char *msg)
{
    /* Obtain a backtrace and print it to stderr. */
    void *array[10];
    size_t size;
    char **strings;
    int i;

    size = backtrace(array, 10);
    strings = backtrace_symbols(array, size);

    fprintf(stderr, "%s\nTraceback:\n", msg);
    for (i = 0; i < size; i++)
        fprintf(stderr, "  %s\n", strings[i]);
    fflush(stderr);
}
