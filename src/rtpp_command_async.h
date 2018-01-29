/*
 * Copyright (c) 2010 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_COMMAND_ASYNC_H_
#define _RTPP_COMMAND_ASYNC_H_

struct rtpp_cmd_async;

DEFINE_METHOD(rtpp_cmd_async, rtpp_cmd_async_dtor, void);
DEFINE_METHOD(rtpp_cmd_async, rtpp_cmd_async_wakeup, int);
DEFINE_METHOD(rtpp_cmd_async, rtpp_cmd_async_get_aload, double);
DEFINE_METHOD(rtpp_cmd_async, rtpp_cmd_reg_overload, void, int);
DEFINE_METHOD(rtpp_cmd_async, rtpp_cmd_chk_overload, int);

struct rtpp_cmd_async {
    rtpp_cmd_async_dtor_t dtor;
    rtpp_cmd_async_wakeup_t wakeup;
    rtpp_cmd_async_get_aload_t get_aload;
    rtpp_cmd_reg_overload_t reg_overload;
    rtpp_cmd_chk_overload_t chk_overload;
};

struct rtpp_cmd_async *rtpp_command_async_ctor(struct cfg *);

#endif
