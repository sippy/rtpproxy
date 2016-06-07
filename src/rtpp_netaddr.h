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

#ifndef _RTPP_NETADDR_H_
#define _RTPP_NETADDR_H_

struct rtpp_netaddr;
struct rtpp_refcnt;
struct sockaddr;

DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_set, void, const struct sockaddr *,
  size_t);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_isempty, int);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_cmp, int, const struct sockaddr *,
  size_t);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_isaddrseq, int,
  const struct sockaddr *);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_cmphost, int,
  const struct sockaddr *);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_copy, void, struct rtpp_netaddr *);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_get, size_t, struct sockaddr *,
  size_t);
DEFINE_METHOD(rtpp_netaddr, rtpp_netaddr_sip_print, size_t, char *, size_t,
  char);

struct rtpp_netaddr_smethods {
    METHOD_ENTRY(rtpp_netaddr_set, set);
    METHOD_ENTRY(rtpp_netaddr_isempty, isempty);
    METHOD_ENTRY(rtpp_netaddr_cmp, cmp);
    METHOD_ENTRY(rtpp_netaddr_isaddrseq, isaddrseq);
    METHOD_ENTRY(rtpp_netaddr_cmphost, cmphost);
    METHOD_ENTRY(rtpp_netaddr_copy, copy);
    METHOD_ENTRY(rtpp_netaddr_get, get);
    METHOD_ENTRY(rtpp_netaddr_sip_print, sip_print);
};

struct rtpp_netaddr {
    struct rtpp_refcnt *rcnt;
    const struct rtpp_netaddr_smethods *smethods;
};

struct rtpp_netaddr *rtpp_netaddr_ctor(void);
#endif
