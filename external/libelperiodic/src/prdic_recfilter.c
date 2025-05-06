/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include "prdic_recfilter.h"
#include "prdic_types.h"
#include "prdic_procchain.h"

double
_prdic_recfilter_apply(struct _prdic_recfilter *f, double x)
{
    double chainval;

    f->lastval = f->a * x + f->b * f->lastval;
    for (int i = 0; f->procchain[i] != NULL; i++) {
        struct _prdic_procchain *clnk;

        if (i == 0)
            chainval = f->lastval;
        clnk = f->procchain[i];
        chainval = clnk->handle(clnk->arg, chainval);
    }
    return f->lastval;
}

void
_prdic_recfilter_init(struct _prdic_recfilter *f, double fcoef, double initval)
{

    f->lastval = initval;
    _prdic_recfilter_adjust(f, fcoef);
}

void
_prdic_recfilter_adjust(struct _prdic_recfilter *f, double fcoef)
{

    assert(fcoef < 1.0 && fcoef > 0.0);
    f->a = 1.0 - fcoef;
    f->b = fcoef;
}
