/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#if !defined(_RTPP_MEMDEB_H)
#define _RTPP_MEMDEB_H

#ifdef LINUX_XXX
/* vasprintf() etc */
#define _GNU_SOURCE    1
/* Apparently needed for drand48(3) */
#define _SVID_SOURCE    1
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <pthread.h>

#include "rtpp_codeptr.h"

#if !defined(MEMDEB_APP)
#error MEMDEB_APP has to be defined
#endif

#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)

CONCAT(CONCAT(extern void *_, MEMDEB_APP), _memdeb);

#define MEMDEB_SYM CONCAT(CONCAT(_, MEMDEB_APP), _memdeb)

#undef malloc
#define malloc(n) rtpp_memdeb_malloc((n), MEMDEB_SYM, HEREVAL)
#undef free
#if !defined(RTPP_MEMDEB_FREE_NULL)
#define free(p) rtpp_memdeb_free((p), MEMDEB_SYM, HEREVAL)
#else
#define free(p) rtpp_memdeb_free_n((p), MEMDEB_SYM, HEREVAL)
#endif
#undef realloc
#define realloc(p,n) rtpp_memdeb_realloc((p), (n), MEMDEB_SYM, HEREVAL)
#undef strdup
#define strdup(p) rtpp_memdeb_strdup((p), MEMDEB_SYM, HEREVAL)
#undef asprintf
#define asprintf(pp, fmt, args...) rtpp_memdeb_asprintf((pp), MEMDEB_SYM, HEREVAL, \
  (fmt), ## args)
#undef vasprintf
#define vasprintf(pp, fmt, vl) rtpp_memdeb_vasprintf((pp), (fmt), \
  MEMDEB_SYM, HEREVAL, (vl))
#undef memcpy
#define memcpy(dp, sp, len) rtpp_memdeb_memcpy((void *)(dp), (void *)(sp), \
  (len), MEMDEB_SYM, HEREVAL)
#define calloc(nm, sz) rtpp_memdeb_calloc((nm), (sz), MEMDEB_SYM, HEREVAL)

void *rtpp_memdeb_malloc(size_t, void *, HERETYPE) RTPP_EXPORT;
void rtpp_memdeb_free(void *, void *, HERETYPE) RTPP_EXPORT;
void rtpp_memdeb_free_n(void *, void *, HERETYPE);
void *rtpp_memdeb_realloc(void *, size_t, void *, HERETYPE) RTPP_EXPORT;
char *rtpp_memdeb_strdup(const char *, void *, HERETYPE);
int rtpp_memdeb_asprintf(char **, void *, HERETYPE, const char *, ...)
   __attribute__ ((format (printf, 4, 5)));
void *rtpp_memdeb_memcpy(void *dst, const void *src, size_t len, void *,
  HERETYPE) RTPP_EXPORT;
void *rtpp_memdeb_calloc(size_t number, size_t size, void *, HERETYPE);

#include <stdarg.h>

int rtpp_memdeb_vasprintf(char **, const char *, void *, HERETYPE, va_list);

#define RTPP_CHECK_LEAKS 	1

#endif
