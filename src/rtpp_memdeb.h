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

#if !defined(MEMDEB_APP)
#error MEMDEB_APP has to be defined
#endif

#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)

CONCAT(CONCAT(extern void *_, MEMDEB_APP), _memdeb);

#define MEMDEB_SYM CONCAT(CONCAT(_, MEMDEB_APP), _memdeb)

#undef malloc
#define malloc(n) rtpp_memdeb_malloc((n), MEMDEB_SYM, \
  __FILE__, __LINE__, __func__)
#undef free
#if !defined(RTPP_MEMDEB_FREE_NULL)
#define free(p) rtpp_memdeb_free((p), MEMDEB_SYM, \
  __FILE__, __LINE__, __func__)
#else
#define free(p) rtpp_memdeb_free_n((p), MEMDEB_SYM, \
  __FILE__, __LINE__, __func__)
#endif
#undef realloc
#define realloc(p,n) rtpp_memdeb_realloc((p), (n), \
  MEMDEB_SYM, __FILE__, __LINE__, __func__)
#undef strdup
#define strdup(p) rtpp_memdeb_strdup((p), MEMDEB_SYM, \
  __FILE__, __LINE__, __func__)
#undef asprintf
#define asprintf(pp, fmt, args...) rtpp_memdeb_asprintf((pp), (fmt), \
  MEMDEB_SYM, __FILE__, __LINE__, __func__, ## args)
#undef vasprintf
#define vasprintf(pp, fmt, vl) rtpp_memdeb_vasprintf((pp), (fmt), \
  MEMDEB_SYM, __FILE__, __LINE__, __func__, (vl))
#undef memcpy
#define memcpy(dp, sp, len) rtpp_memdeb_memcpy((dp), (sp), (len), \
  MEMDEB_SYM, __FILE__, __LINE__, __func__)
#define calloc(nm, sz) rtpp_memdeb_calloc((nm), (sz), \
  MEMDEB_SYM, __FILE__, __LINE__, __func__)

void *rtpp_memdeb_malloc(size_t, void *, const char *, int, const char *);
void rtpp_memdeb_free(void *, void *, const char *, int, const char *);
void rtpp_memdeb_free_n(void *, void *, const char *, int, const char *);
void *rtpp_memdeb_realloc(void *, size_t, void *, const char *, int, const char *);
char *rtpp_memdeb_strdup(const char *, void *, const char *, int, const char *);
int rtpp_memdeb_asprintf(char **, const char *, void *, const char *, int, \
  const char *, ...);
void *rtpp_memdeb_memcpy(void *dst, const void *src, size_t len, void *, \
  const char *, int, const char *);
void *rtpp_memdeb_calloc(size_t number, size_t size, void *, \
  const char *, int, const char *);

#include <stdarg.h>

int rtpp_memdeb_vasprintf(char **, const char *, void *, const char *, int, \
  const char *, va_list);

#define RTPP_CHECK_LEAKS 	1

#endif
