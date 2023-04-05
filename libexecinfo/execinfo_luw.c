/*
 * Copyright (c) 2003-2023 Maxim Sobolev <sobomax@FreeBSD.org>
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
 */

#include <stddef.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "execinfo_internal.h"
#include "execinfo.h"
#include "stacktraverse.h"

void *
getreturnaddr(int level)
{
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip;
    int i;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    for (i = 0; i < level + 1 && unw_step(&cursor) > 0; i++) {
       if (unw_get_reg(&cursor, UNW_REG_IP, &ip) != 0)
           return (NULL);
    }
    if (i != level + 1)
        return (NULL);
    return ((void *)ip);
}

int
backtrace(void **buffer, int size)
{
    int i;
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    if (size > STACKTRAVERSE_MAX_LEVELS)
        size = STACKTRAVERSE_MAX_LEVELS;
    for (i = 0; i < size + 1 && unw_step(&cursor) > 0; i++) {
        if (i < 1)
            continue;
        if (unw_get_reg(&cursor, UNW_REG_IP, &ip) != 0)
            return -1;
        buffer[i - 1] = (void *)ip;
        if ((void *)ip == libexecinfo_ns.topframe)
            return i;
        if ((void *)ip == NULL)
            break;
    }

    return i - 1;
}

uintptr_t
getstackcookie(void)
{
    int i;
    uintptr_t r, tr;
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    r = 0;
    for (i = 1; i < STACKTRAVERSE_MAX_LEVELS + 1 && unw_step(&cursor) > 0; i++) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        tr = ROR((uintptr_t)ip, libexecinfo_ns.sc_randtable[i - 1]);
        r ^= tr;
    }
    return (r);
}
