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

struct rtpp_refcnt_obj;

typedef void (*rtpp_refcnt_dtor_t)(void *);

DEFINE_METHOD(rtpp_refcnt_obj, refcnt_incref, void);
DEFINE_METHOD(rtpp_refcnt_obj, refcnt_decref, void);
DEFINE_METHOD(rtpp_refcnt_obj, refcnt_getdata, void *);
DEFINE_METHOD(rtpp_refcnt_obj, refcnt_reg_pd, void, rtpp_refcnt_dtor_t, void *);
DEFINE_METHOD(rtpp_refcnt_obj, refcnt_abort, void);

struct rtpp_refcnt_obj
{
    refcnt_incref_t incref;
    refcnt_decref_t decref;
    refcnt_getdata_t getdata;
    refcnt_reg_pd_t reg_pd;
    refcnt_abort_t abort;
};

struct rtpp_refcnt_obj *rtpp_refcnt_ctor(void *, rtpp_refcnt_dtor_t);
size_t rtpp_refcnt_osize(void);
struct rtpp_refcnt_obj *rtpp_refcnt_ctor_pa(void *, void *, rtpp_refcnt_dtor_t);
