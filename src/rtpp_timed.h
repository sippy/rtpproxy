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

enum rtpp_timed_cb_rvals {CB_LAST, CB_MORE};

typedef enum rtpp_timed_cb_rvals (*rtpp_timed_cb_t)(double, void *);
typedef void (*rtpp_timed_cancel_cb_t)(void *);

struct rtpp_timed;
struct rtpp_timed_task;
struct rtpp_refcnt;

DEFINE_METHOD(rtpp_timed_task, rtpp_timed_task_cancel, int);

struct rtpp_timed_task {
    struct rtpp_refcnt *rcnt;
    METHOD_ENTRY(rtpp_timed_task_cancel, cancel);
};

DEFINE_METHOD(rtpp_timed, rtpp_timed_schedule, int, double,
  rtpp_timed_cb_t, rtpp_timed_cancel_cb_t, void *);
DEFINE_METHOD(rtpp_timed, rtpp_timed_schedule_rc, struct rtpp_timed_task *,
  double, struct rtpp_refcnt *, rtpp_timed_cb_t, rtpp_timed_cancel_cb_t, void *);

struct rtpp_timed {
    METHOD_ENTRY(rtpp_timed_schedule, schedule);
    METHOD_ENTRY(rtpp_timed_schedule_rc, schedule_rc);
    struct rtpp_refcnt *rcnt;
};

struct rtpp_timed *rtpp_timed_ctor(double);
