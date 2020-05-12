/*
 * Copyright (c) 2020 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_MODMAN_H
#define _RTPP_MODMAN_H

struct rtpp_modman;
struct rtpp_refcnt;
struct rtpp_module_if;
struct rtpp_cfg;
struct rtpp_acct;
struct after_success_h;

DEFINE_METHOD(rtpp_modman, rtpp_modman_insert, void, struct rtpp_module_if *);
DEFINE_METHOD(rtpp_modman, rtpp_modman_startall, int, const struct rtpp_cfg *,
  const char **);
DEFINE_METHOD(rtpp_modman, rtpp_modman_get_next_id, unsigned int,
  unsigned int);
DEFINE_METHOD(rtpp_modman, rtpp_modman_do_acct, void, struct rtpp_acct *);
DEFINE_METHOD(rtpp_modman, rtpp_modman_get_ul_subc_h, int, unsigned int,
  unsigned int, struct after_success_h *);

struct rtpp_modman {
    struct rtpp_refcnt *rcnt;
    struct {
        unsigned int total;
        unsigned int sess_acct;
    } count;
    METHOD_ENTRY(rtpp_modman_insert, insert);
    METHOD_ENTRY(rtpp_modman_startall, startall);
    METHOD_ENTRY(rtpp_modman_get_next_id, get_next_id);
    METHOD_ENTRY(rtpp_modman_do_acct, do_acct);
    METHOD_ENTRY(rtpp_modman_get_ul_subc_h, get_ul_subc_h);
};

struct rtpp_modman *rtpp_modman_ctor(void);

#endif /* _RTPP_MODMAN_H */
