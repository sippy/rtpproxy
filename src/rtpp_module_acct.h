/*
 * Copyright (c) 2016-2020 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_MODULE_ACCT_H
#define _RTPP_MODULE_ACCT_H

struct rtpp_acct;
struct rtpp_acct_rtcp;

DEFINE_METHOD(rtpp_module_priv, rtpp_module_on_session_end, void,
  struct rtpp_acct *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_on_rtcp_rcvd, void,
  struct rtpp_acct_rtcp *);

#define AAPI_FUNC(fname, asize) {.func = (fname), .argsize = (asize)}

struct api_on_sess_end {
   size_t argsize;
   rtpp_module_on_session_end_t func;
};

struct api_on_rtcp_rcvd {
   size_t argsize;
   rtpp_module_on_rtcp_rcvd_t func;
};

struct rtpp_acct_handlers {
    struct api_on_sess_end on_session_end;
    struct api_on_rtcp_rcvd on_rtcp_rcvd;
};

#endif /* _RTPP_MODULE_ACCT_H */
