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

#ifndef _RTPP_DEBUG_H_
#define _RTPP_DEBUG_H_

#if defined(RTPP_DEBUG)
/* Supported levels 0, 1, 2. 1 - basic debug & debug when I/O fails, 2 - debug on every packet */
#define RTPP_DEBUG_netio      1
/* Supported levels 0, 1. */
#define RTPP_DEBUG_timers     0
/* Catch fatal signals and try to pring backtrace */
#define RTPP_DEBUG_catchtrace 0
#define RTPP_DEBUG_refcnt     0
#define RTPP_DEBUG_analyze    1
#else
#define RTPP_DEBUG_netio      0
#define RTPP_DEBUG_timers     0
#define RTPP_DEBUG_catchtrace 0
#define RTPP_DEBUG_refcnt     0
#define RTPP_DEBUG_analyze    0
#endif

#if defined(RTPP_DEBUG)
#include <assert.h>

#define RTPP_DBG_ASSERT(...)  assert(__VA_ARGS__)
#else
#define RTPP_DBG_ASSERT(...)
#endif

#endif
