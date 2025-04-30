/*
 * Copyright (c) 2018 Sippy Software, Inc., http://www.sippysoft.com
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

#pragma once

struct rtpp_sbuf {
   int alen;
   char *bp;
   char *cp;
};

#define SBW_OK    (0)
#define SBW_ERR  (-1)
#define SBW_SHRT (-2)

#define RS_ULEN(sbp) ((int)((sbp)->cp - (sbp)->bp))

int rtpp_sbuf_write(struct rtpp_sbuf *sbp, const char *format, ...)
  __attribute__ ((format (printf, 2, 3))) RTPP_EXPORT;
#if !defined(RTPP_CHECK_LEAKS)
struct rtpp_sbuf *rtpp_sbuf_ctor(int ilen) RTPP_EXPORT;
int rtpp_sbuf_extend(struct rtpp_sbuf *sbp, int nlen) RTPP_EXPORT;
void rtpp_sbuf_dtor(struct rtpp_sbuf *sbp) RTPP_EXPORT;
#else
struct rtpp_sbuf *_rtpp_sbuf_ctor(int ilen, void *, HERETYPE) RTPP_EXPORT;
int _rtpp_sbuf_extend(struct rtpp_sbuf *sbp, int nlen, void *, HERETYPE) RTPP_EXPORT;
void _rtpp_sbuf_dtor(struct rtpp_sbuf *sbp, void *, HERETYPE) RTPP_EXPORT;
#define rtpp_sbuf_ctor(ilen) _rtpp_sbuf_ctor(ilen, MEMDEB_SYM, HEREVAL)
#define rtpp_sbuf_extend(sbp, nlen) _rtpp_sbuf_extend(sbp, nlen, MEMDEB_SYM, HEREVAL)
#define rtpp_sbuf_dtor(sbp) _rtpp_sbuf_dtor(sbp, MEMDEB_SYM, HEREVAL)
#endif
void rtpp_sbuf_reset(struct rtpp_sbuf *sbp) RTPP_EXPORT;
