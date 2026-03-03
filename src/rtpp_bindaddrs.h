/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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

struct sockaddr;
struct rtpp_bindaddr;
struct rtpp_cfg;
struct rtpp_log;

DECLARE_CLASS(rtpp_bindaddrs, void);

DECLARE_METHOD(rtpp_bindaddrs, addr2bindaddr, const struct sockaddr *,
  const struct sockaddr *, const char **);
DECLARE_METHOD(rtpp_bindaddrs, host2bindaddr, const struct sockaddr *,
  const char *, int, int, const char **);
DECLARE_METHOD(rtpp_bindaddrs, bindaddr4af, const struct sockaddr *, int);
DECLARE_METHOD(rtpp_bindaddrs, local4remote, const struct sockaddr *,
  const struct rtpp_cfg *, struct rtpp_log *, int, const char *, const char *);

DECLARE_SMETHODS(rtpp_bindaddrs) {
    METHOD_ENTRY(addr2bindaddr, addr2);
    METHOD_ENTRY(host2bindaddr, host2);
    METHOD_ENTRY(bindaddr4af,  foraf);
    METHOD_ENTRY(local4remote, local4remote);
};

DECLARE_CLASS_PUBTYPE(rtpp_bindaddrs, {});
