/*
 * Copyright (c) 2003 Maxim Sobolev <sobomax@FreeBSD.org>
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
 * $Id: execinfo.c,v 1.3 2004/07/19 05:21:09 sobomax Exp $
 */

#if defined(LINUX_XXX)
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "execinfo.h"
#include "execinfo_internal.h"
#include "stacktraverse.h"

struct libexecinfo_ns libexecinfo_ns = {
    .sc_randtable = {
        23,  3, 50, 54,  6, 63, 58, 61, 12,  4, 46, 36, 52, 35, 28, 55, 11, 29, 60,
        38, 37, 53,  7, 26,  2, 39,  0, 30, 14, 56, 48, 27, 33, 47, 24, 57, 20, 34,
        31, 15, 51, 13, 32,  8,  1, 49, 22, 21, 45, 41, 62, 40, 19, 44, 17, 10, 59,
        18,  5, 16,  9, 25, 43, 42, 55, 14, 46,  6, 20, 29, 48, 12, 63, 31, 60, 34,
        61, 32, 37, 36, 22, 45, 58,  8, 54, 24, 44, 49, 41, 11,  5, 15,  1, 56,  4,
        21, 10,  3,  9,  2, 13, 47, 50, 57, 51, 26, 17, 35, 18,  0, 53, 59, 43, 52,
        30, 27, 19, 38, 42, 23, 25, 40,  7, 62, 33, 28, 39, 16
    },
};

static int
get_d10(int val)
{
    int c;

    if (val < 0) {
        c = 2;
        val = -val;
    } else {
        c = 1;
    }
    for (; val >= 10; val = val / 10) {
        c += 1;
    }
    return (c);
}

const void *
execinfo_set_topframe(const void *tfp)
{
    const void *otfp;

    otfp = libexecinfo_ns.topframe;
    libexecinfo_ns.topframe = tfp;
    return (otfp);
}

#if !defined(USE_LIBUNWIND)
int
backtrace(void **buffer, int size)
{
    int i;

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    for (i = 1; i < size + 1 && getframeaddr(i) != NULL; i++) {
        buffer[i - 1] = getreturnaddr(i);
        if (buffer[i - 1] == NULL)
            break;
	if (buffer[i - 1] == libexecinfo_ns.topframe)
	    return i;
    }

    return i - 1;
}

uintptr_t
getstackcookie(void)
{
    int i;
    uintptr_t r, tr;
    void *p;

    r = 0;
    for (i = 1; i < STACKTRAVERSE_MAX_LEVELS + 1 && getframeaddr(i) != NULL; i++) {
        p = getreturnaddr(i);
        tr = ROR((uintptr_t)p, libexecinfo_ns.sc_randtable[i - 1]);
        r ^= tr;
        if (p == libexecinfo_ns.topframe || p == NULL)
            break;
    }
    return (r);
}
#endif

char **
backtrace_symbols(void *const *buffer, int size)
{
    int i, offset, bsize, alen;
    Dl_info info;
    char *bp;

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    bp = libexecinfo_ns.bt_buffer;
    bsize = sizeof(libexecinfo_ns.bt_buffer);
    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = (char *)buffer[i] - (char *)info.dli_saddr;
            /* "#0      0x01234567 in <function+offset> at filename" */
            alen = 1 + get_d10(i) + 1 +     /* "#0\t" */
                   2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   5 +                      /* " in <" */
                   strlen(info.dli_sname) + /* "function" */
                   1 +                      /* "+" */
                   get_d10(offset) +        /* "offset" */
                   5 +                      /* "> at " */
                   strlen(info.dli_fname) + /* "filename" */
                   1;                       /* "\0" */
            snprintf(bp, bsize, "#%d\t%p in <%s+%d> at %s", i,
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            alen = 1 + get_d10(i) + 1 +     /* "#0\t" */
                   2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   1;                       /* "\0" */
            snprintf(bp, bsize, "#%d\t%p", i, buffer[i]);
        }
        libexecinfo_ns.bt_rvals[i] = bp;
        bp += alen;
        bsize -= alen;
        if (bsize <= 0) {
            for (i = i + 1; i < size; i++) {
                libexecinfo_ns.bt_rvals[i] = NULL;
            }
            break;
        }
    }

    return libexecinfo_ns.bt_rvals;
}

void
backtrace_symbols_fd(void *const *buffer, int size, int fd)
{
    int i, len, offset;
    char *buf;
    Dl_info info;

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = (char *)buffer[i] - (char *)info.dli_saddr;
            /* "#0      0x01234567 in <function+offset> at filename" */
            len = 1 + get_d10(i) + 1 +     /* "#0\t" */
                  2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  5 +                      /* " in <" */
                  strlen(info.dli_sname) + /* "function" */
                  1 +                      /* "+" */
                  get_d10(offset) +        /* "offset" */
                  5 +                      /* "> at " */
                  strlen(info.dli_fname) + /* "filename" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "#%d\t%p in <%s+%d> at %s\n", i,
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            len = 1 + get_d10(i) + 1 +     /* "#0 " */
                  2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "#%d\t%p\n", i, buffer[i]);
        }
        write(fd, buf, strlen(buf));
    }
}

#if defined(execinfo_TEST)
#include <assert.h>
#include <stdio.h>

int
execinfo_TEST(void)
{
  void *faketrace[] = {(void *)0xdeadbeef, (void *)0xbadc00de, execinfo_TEST, NULL};

  assert(get_d10(-1) == 2);
  assert(get_d10(-100) == 4);
  backtrace_symbols_fd(faketrace, 4, fileno(stdout));
  assert(backtrace_symbols(faketrace, 4) != NULL);
}
#endif
