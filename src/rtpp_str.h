/*
 * Copyright (c) 2023 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_str_mutble {
    char *s;
    size_t len;
};

struct rtpp_str_const {
    const char *s;
    size_t len;
};

struct rtpp_str_fixed {
    const char * const s;
    const size_t len;
};

typedef struct rtpp_str_mutble rtpp_str_mutble_t;
typedef struct rtpp_str_const rtpp_str_const_t;
typedef struct rtpp_str_fixed rtpp_str_t;

struct rtpp_str {
    union {
        rtpp_str_mutble_t rw;
        rtpp_str_const_t ro;
        const rtpp_str_t fx;
    };
};

#define rtpp_str_fix(src) ((const rtpp_str_t *)(src))

#define rtpp_str_dup2(src, dst) _Generic((src), \
    rtpp_str_const_t *: _rtpp_str_dup2_sc, \
    const rtpp_str_t *: _rtpp_str_dup2_sf, \
    struct rtpp_str *: _rtpp_str_dup2 \
)(src, dst)

#define rtpp_str_match(sp1, sp2) (((sp1)->len == (sp2)->len) && \
  memcmp((sp1)->s, (sp2)->s, (sp1)->len) == 0)

#define FMTSTR(sp) (int)(sp)->len, (sp)->s

#define RTPP_STR_ITERATE(sp, cp) for((cp) = (sp)->s; (cp) < ((sp)->s + (sp)->len); (cp)++)

struct rtpp_str *_rtpp_str_dup2(const struct rtpp_str *,
  struct rtpp_str *dst);

static inline struct rtpp_str *
_rtpp_str_dup2_sc(const struct rtpp_str_const *src, struct rtpp_str_const *dst)
{

    return (_rtpp_str_dup2((const struct rtpp_str *)src, (struct rtpp_str *)dst));
}

static inline struct rtpp_str *
_rtpp_str_dup2_sf(const struct rtpp_str_fixed *src, struct rtpp_str_const *dst)
{

    return (_rtpp_str_dup2((const struct rtpp_str *)src, (struct rtpp_str *)dst));
}
