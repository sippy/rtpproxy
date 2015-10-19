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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "execinfo.h"
#include "stacktraverse.h"

#define LINELEN_MAX 512

static char bt_buffer[STACKTRAVERSE_MAX_LEVELS * LINELEN_MAX];
static char *bt_rvals[STACKTRAVERSE_MAX_LEVELS];

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

int
backtrace(void **buffer, int size)
{
    int i;

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    for (i = 1; getframeaddr(i + 1) != NULL && i != size + 1; i++) {
        buffer[i - 1] = getreturnaddr(i);
        if (buffer[i - 1] == NULL)
            break;
    }

    return i - 1;
}

char **
backtrace_symbols(void *const *buffer, int size)
{
    int i, offset, bsize, alen;
    Dl_info info;
    char *bp;

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    bp = bt_buffer;
    bsize = sizeof(bt_buffer);
    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = (char *)buffer[i] - (char *)info.dli_saddr;
            /* "0x01234567 <function+offset> at filename" */
            alen = 2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   2 +                      /* " <" */
                   strlen(info.dli_sname) + /* "function" */
                   1 +                      /* "+" */
                   get_d10(offset) +        /* "offset" */
                   5 +                      /* "> at " */
                   strlen(info.dli_fname) + /* "filename" */
                   1;                       /* "\0" */
            snprintf(bp, bsize, "%p <%s+%d> at %s",
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            alen = 2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   1;                       /* "\0" */
            snprintf(bp, bsize, "%p", buffer[i]);
        }
        bt_rvals[i] = bp;
        bp += alen;
        bsize -= alen;
        if (bsize <= 0) {
            for (i = i + 1; i < size; i++) {
                bt_rvals[i] = NULL;
            }
            break;
        }
    }

    return bt_rvals;
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
            /* "0x01234567 <function+offset> at filename" */
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2 +                      /* " <" */
                  strlen(info.dli_sname) + /* "function" */
                  1 +                      /* "+" */
                  get_d10(offset) +        /* "offset" */
                  5 +                      /* "> at " */
                  strlen(info.dli_fname) + /* "filename" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p <%s+%d> at %s\n",
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p\n", buffer[i]);
        }
        write(fd, buf, strlen(buf));
    }
}
