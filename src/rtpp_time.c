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

#include <math.h>
#include <stdint.h>
#include <time.h>

#include "rtpp_time.h"

static double timespec2dtime(time_t, long);

double
getdtime(void)
{
    struct timespec tp;

    if (clock_gettime(RTPP_CLOCK_MONO, &tp) == -1)
        return (-1);

    return timespec2dtime(tp.tv_sec, tp.tv_nsec);
}

static double
timespec2dtime(time_t tv_sec, long tv_nsec)
{

    return (double)tv_sec + (double)tv_nsec / 1000000000.0;
}

double
ts2dtime(uint32_t ts_sec, uint32_t ts_usec)
{

    return ts_sec + ((double)ts_usec) / 1000000.0;
}

void
dtime2ts(double dtime, uint32_t *ts_sec, uint32_t *ts_usec)
{

    *ts_sec = trunc(dtime);
    *ts_usec = round(1000000.0 * (dtime - ((double)*ts_sec)));
}
