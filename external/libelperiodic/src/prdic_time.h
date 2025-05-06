/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
 * Copyright (c) 2016-2018, Maksym Sobolyev <sobomax@sippysoft.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _PRDIC_TIME_H_
#define _PRDIC_TIME_H_

static inline int
getttime(struct timespec *ttp, int abort_on_fail)
{

    if (clock_gettime(CLOCK_MONOTONIC, ttp) == -1) {
        if (abort_on_fail)
            abort();
        return (-1);
    }
    return (0);
}

#if 0
static void
dtime2timespec(double dtime, struct timespec *ttp)
{

    SEC(ttp) = trunc(dtime);
    dtime -= (double)SEC(ttp);
    NSEC(ttp) = round((double)NSEC_IN_SEC * dtime);
}
#endif

static inline void
tplusdtime(struct timespec *ttp, double offset)
{
    struct timespec tp;

    dtime2timespec(offset, &tp);
    timespecadd(ttp, &tp);
}

#endif /* _PRDIC_TIME_H_ */
