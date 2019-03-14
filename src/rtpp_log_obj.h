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

struct rtpp_cfg_stable;
struct rtpp_log;

DEFINE_METHOD(rtpp_log, rtpp_log_write, void, const char *, int,
  const char *, ...) __attribute__ ((format (printf, 4, 5)));
DEFINE_METHOD(rtpp_log, rtpp_log_ewrite, void, const char *, int,
  const char *, ...) __attribute__ ((format (printf, 4, 5)));
DEFINE_METHOD(rtpp_log, rtpp_log_setlevel, void, int);
DEFINE_METHOD(rtpp_log, rtpp_log_start, int, struct rtpp_cfg_stable *);

struct rtpp_log {
    struct rtpp_refcnt *rcnt;
    /* Public methods */
    METHOD_ENTRY(rtpp_log_write, write);
    METHOD_ENTRY(rtpp_log_ewrite, ewrite);
    METHOD_ENTRY(rtpp_log_setlevel, setlevel);
    METHOD_ENTRY(rtpp_log_start, start);
    /* UID */
    uint64_t lguid;
};

struct rtpp_log *rtpp_log_ctor(const char *, const char *, int);

#define RTPP_LOG(log, args...) CALL_METHOD((log), write, __FUNCTION__, \
  ## args)
#define RTPP_ELOG(log, args...) CALL_METHOD((log), ewrite, __FUNCTION__, \
  ## args)
