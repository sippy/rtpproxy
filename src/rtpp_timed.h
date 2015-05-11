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

typedef void (*rtpp_timed_cb_t)(double, void *);
typedef void (*rtpp_timed_cancel_cb_t)(void *);

struct rtpp_wi;
struct rtpp_timed_obj;

DEFINE_METHOD(rtpp_timed_obj, rtpp_timed_dtor, void);
DEFINE_METHOD(rtpp_timed_obj, rtpp_timed_process, void, double);
DEFINE_METHOD(rtpp_timed_obj, rtpp_timed_schedule, struct rtpp_wi *, double,
  rtpp_timed_cb_t, rtpp_timed_cancel_cb_t, void *);
DEFINE_METHOD(rtpp_timed_obj, rtpp_timed_cancel, int, struct rtpp_wi *);

struct rtpp_timed_obj {
    rtpp_timed_dtor_t dtor;
    rtpp_timed_process_t process;
    rtpp_timed_schedule_t schedule;
    rtpp_timed_cancel_t cancel;
};

struct rtpp_timed_obj *rtpp_timed_ctor(void);
