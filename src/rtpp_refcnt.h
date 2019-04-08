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

#if !defined(_RTPP_REFCNT_H)
#define _RTPP_REFCNT_H

struct rtpp_refcnt;

typedef void (*rtpp_refcnt_dtor_t)(void *);

DEFINE_METHOD(rtpp_refcnt, refcnt_incref, void);
DEFINE_METHOD(rtpp_refcnt, refcnt_decref, void);
DEFINE_METHOD(rtpp_refcnt, refcnt_getdata, void *);
DEFINE_METHOD(rtpp_refcnt, refcnt_reg_pd, void, rtpp_refcnt_dtor_t, void *);
DEFINE_METHOD(rtpp_refcnt, refcnt_attach, void, rtpp_refcnt_dtor_t, void *);
DEFINE_METHOD(rtpp_refcnt, refcnt_traceen, void);

struct rtpp_refcnt_smethods
{
    METHOD_ENTRY(refcnt_incref, incref);
    METHOD_ENTRY(refcnt_decref, decref);
    METHOD_ENTRY(refcnt_getdata, getdata);
    METHOD_ENTRY(refcnt_reg_pd, reg_pd);
    METHOD_ENTRY(refcnt_attach, attach);
    METHOD_ENTRY(refcnt_traceen, traceen);
};

struct rtpp_refcnt
{
#if defined(RTPP_FINTEST)
    struct rtpp_refcnt *rcnt;
#endif
    const struct rtpp_refcnt_smethods *smethods;
};

struct rtpp_refcnt *rtpp_refcnt_ctor(void *, rtpp_refcnt_dtor_t);
const unsigned int rtpp_refcnt_osize(void);
struct rtpp_refcnt *rtpp_refcnt_ctor_pa(void *);

#endif /* _RTPP_REFCNT_H */
