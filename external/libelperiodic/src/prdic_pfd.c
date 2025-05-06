/*
 * Copyright (c) 2014-2019 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#include <sys/time.h>
#include <assert.h>
#include <math.h>
#include <string.h>

#include "prdic_math.h"
#include "prdic_timespecops.h"
#include "prdic_pfd.h"

void
_prdic_PFD_init(struct _prdic_PFD *pfd_p)
{

    memset(pfd_p, '\0', sizeof(struct _prdic_PFD));
}

double
_prdic_PFD_get_error(struct _prdic_PFD *pfd_p, const struct timespec *tclk)
{
    double err0r;
    struct timespec next_tclk, ttclk;

    SEC(&next_tclk) = SEC(tclk) + 1;
    NSEC(&next_tclk) = 0;
    if (timespeciszero(&pfd_p->target_tclk)) {
        pfd_p->target_tclk = next_tclk;
        return (0.0);
    }

    timespecsub2(&ttclk, &pfd_p->target_tclk, tclk);
    err0r = timespec2dtime(&ttclk);

    pfd_p->target_tclk = next_tclk;
    if (err0r > 0) {
        SEC(&pfd_p->target_tclk) += 1;
    }

    return (err0r);
}

void
_prdic_PFD_reset(struct _prdic_PFD *pfd_p)
{

    SEC(&pfd_p->target_tclk) = 0;
    NSEC(&pfd_p->target_tclk) = 0;
}
