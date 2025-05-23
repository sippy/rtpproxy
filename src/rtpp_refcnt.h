/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_codeptr;

#define MAX_DTORS 24

typedef void (*rtpp_refcnt_dtor_t)(void *);

DECLARE_CLASS(rtpp_refcnt, void *, rtpp_refcnt_dtor_t);

DECLARE_METHOD(rtpp_refcnt, refcnt_incref, void, const struct rtpp_codeptr *);
DECLARE_METHOD(rtpp_refcnt, refcnt_decref, void, const struct rtpp_codeptr *);
DECLARE_METHOD(rtpp_refcnt, refcnt_getdata, void *);
DECLARE_METHOD(rtpp_refcnt, refcnt_attach, void, rtpp_refcnt_dtor_t, void *);
DECLARE_METHOD(rtpp_refcnt, refcnt_attach_rc, void, struct rtpp_refcnt *);
DECLARE_METHOD(rtpp_refcnt, refcnt_traceen, void, const struct rtpp_codeptr *);
DECLARE_METHOD(rtpp_refcnt, refcnt_peek, int);

DECLARE_SMETHODS(rtpp_refcnt)
{
    METHOD_ENTRY(refcnt_incref, incref);
    METHOD_ENTRY(refcnt_decref, decref);
    METHOD_ENTRY(refcnt_getdata, getdata);
    METHOD_ENTRY(refcnt_attach, attach);
    METHOD_ENTRY(refcnt_attach_rc, attach_rc);
    METHOD_ENTRY(refcnt_traceen, traceen);
    METHOD_ENTRY(refcnt_peek, peek);
};

struct rtpp_refcnt
{
#if defined(RTPP_FINTEST)
    struct rtpp_refcnt *rcnt;
#endif
#if defined(RTPP_DEBUG)
    const struct rtpp_refcnt_smethods * smethods;
#endif
};

extern const size_t rtpp_refcnt_osize;
rtpp_refcnt_rot *rtpp_refcnt_ctor_pa(void *, void *);

#define _GET_ARG_3(_1, _2, _3, ...) _3
#define _RC_CHOOSE(NAME, ...) _GET_ARG_3(__VA_ARGS__, NAME##_2, NAME##_1,)
#define _RC_REF_1(rp, method) CALL_SMETHOD(rp, method, HEREVAL)
#define _RC_REF_2(rp, method, harg) CALL_SMETHOD(rp, method, harg)
#define RC_INCREF(rp, ...) _RC_CHOOSE(_RC_REF, __VA_ARGS__)(rp, incref, ##__VA_ARGS__)
#define RC_DECREF(rp, ...) _RC_CHOOSE(_RC_REF, __VA_ARGS__)(rp, decref, ##__VA_ARGS__)
