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
#include "prdic_fd.h"

void
_prdic_FD_init(struct _prdic_FD *fd_p)
{

    memset(fd_p, '\0', sizeof(struct _prdic_FD));
}

double
_prdic_FD_get_error(struct _prdic_FD *fd_p, const struct timespec *tclk)
{
    double err0r;
    struct timespec ttclk;

    if (timespeciszero(&fd_p->last_tclk)) {
        fd_p->last_tclk = *tclk;
        return (0.0);
    }
    timespecsub2(&ttclk, tclk, &fd_p->last_tclk);
    err0r = timespec2dtime(&ttclk);
    fd_p->last_tclk = *tclk;
    return (1.0 - err0r);
}

void
_prdic_FD_reset(struct _prdic_FD *fd_p)
{

    SEC(&fd_p->last_tclk) = 0;
    NSEC(&fd_p->last_tclk) = 0;
}
