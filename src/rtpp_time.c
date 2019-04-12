/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/time.h>
#include <math.h>
#include <time.h>

#include "rtpp_time.h"

static double
_getdtime(clockid_t clock_id)
{
    struct timespec tp;

    if (clock_gettime(clock_id, &tp) == -1)
        return (-1);

    return timespec2dtime(&tp);
}

double
getdtime(void)
{

    return (_getdtime(RTPP_CLOCK_MONO));
}

void
rtpp_timestamp_get(struct rtpp_timestamp *tp)
{

    tp->wall = _getdtime(RTPP_CLOCK_REAL);
    tp->mono = _getdtime(RTPP_CLOCK_MONO);
}

void
dtime2mtimespec(double dtime, struct timespec *mtime)
{

    SEC(mtime) = trunc(dtime);
    NSEC(mtime) = round((double)NSEC_MAX * (dtime - (double)SEC(mtime)));
}

void
dtime2timeval(double dtime, struct timeval *tvp)
{

    SEC(tvp) = trunc(dtime);
    USEC(tvp) = round((double)USEC_MAX * (dtime - (double)SEC(tvp)));
}

const char *
get_mclock_name(void)
{

    return (RTPP_MCLOCK_NAME);
}
