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

struct rtpp_tnotify_set;
struct rtpp_tnotify_target;

DEFINE_METHOD(rtpp_tnotify_set, rtpp_tn_set_dtor, void);
DEFINE_METHOD(rtpp_tnotify_set, rtpp_tn_set_append, int, const char *, const char **);
DEFINE_METHOD(rtpp_tnotify_set, rtpp_tn_set_lookup, struct rtpp_tnotify_target *,
  const char *, struct sockaddr *, struct sockaddr *);
DEFINE_METHOD(rtpp_tnotify_set, rtpp_tn_set_isenabled, int);

struct rtpp_tnotify_set {
    rtpp_tn_set_dtor_t dtor;
    rtpp_tn_set_append_t append;
    rtpp_tn_set_lookup_t lookup;
    rtpp_tn_set_isenabled_t isenabled;
};

struct rtpp_tnotify_set *rtpp_tnotify_set_ctor(void);
