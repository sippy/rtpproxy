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

struct timeval;
struct timespec;

#ifndef _RTPP_TIME_H_
#define _RTPP_TIME_H_

#if defined(CLOCK_UPTIME_PRECISE)
# define RTPP_CLOCK_MONO CLOCK_UPTIME_PRECISE
# define RTPP_MCLOCK_NAME "CLOCK_UPTIME_PRECISE"
#else
# if defined(CLOCK_BOOTTIME)
#  define RTPP_CLOCK_MONO CLOCK_BOOTTIME
#  define RTPP_MCLOCK_NAME "CLOCK_BOOTTIME"
# else
#  define RTPP_CLOCK_MONO CLOCK_MONOTONIC
#  define RTPP_MCLOCK_NAME "CLOCK_MONOTONIC"
# endif
#endif

#if defined(CLOCK_REALTIME_PRECISE)
# define RTPP_CLOCK_REAL CLOCK_REALTIME_PRECISE
# define RTPP_RCLOCK_NAME "CLOCK_REALTIME_PRECISE"
#else
# define RTPP_CLOCK_REAL CLOCK_REALTIME
# define RTPP_RCLOCK_NAME "CLOCK_REALTIME"
#endif

#define SEC(x)   ((x)->tv_sec)
#define NSEC(x)  ((x)->tv_nsec)
#define NSEC_MAX 1000000000L
#define USEC_MAX 1000000L
#define USEC(x)  ((x)->tv_usec)

#define timespeciszero(t)                                          \
    (SEC(t) == 0 && NSEC(t) == 0)
#define timevaliszero(v)                                           \
    (SEC(v) == 0 && USEC(v) == 0)

#define timespec2dtime(s) ((double)SEC(s) + \
  (double)NSEC(s) / 1000000000.0)
#define ts2dtime(ts_sec, ts_usec) ((double)(ts_sec) + \
  (double)(ts_usec) / 1000000.0)
#define timeval2dtime(s) ((double)SEC(s) + \
  (double)USEC(s) / 1000000.0)

struct rtpp_timestamp {
   double wall;
   double mono;
};

/* Function prototypes */
double getdtime(void);
void dtime2mtimespec(double, struct timespec *);
const char *get_mclock_name(void);
void rtpp_timestamp_get(struct rtpp_timestamp *);
void dtime2timeval(double dtime, struct timeval *tvp);

#endif
