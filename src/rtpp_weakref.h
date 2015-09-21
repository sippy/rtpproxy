/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_weakref_obj;
struct rtpp_refcnt_obj;

DEFINE_METHOD(rtpp_weakref_obj, rtpp_wref_reg, uint64_t,
  struct rtpp_refcnt_obj *);
DEFINE_METHOD(rtpp_weakref_obj, rtpp_wref_unreg, struct rtpp_refcnt_obj *,
  uint64_t);
DEFINE_METHOD(rtpp_weakref_obj, rtpp_wref_get_by_idx, struct rtpp_refcnt_obj *,
  uint64_t);
DEFINE_METHOD(rtpp_weakref_obj, rtpp_weakref_dtor, void);

struct rtpp_weakref_obj {
    rtpp_wref_reg_t reg;
    rtpp_wref_unreg_t unreg;
    rtpp_weakref_dtor_t dtor;
    rtpp_wref_get_by_idx_t get_by_idx;
};

struct rtpp_weakref_obj *rtpp_weakref_ctor(void);
