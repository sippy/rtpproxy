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

#include <sys/time.h>
#include <assert.h>
#include <math.h>
#define PRD_DEBUG 0
#if PRD_DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "elperiodic.h"
#include "prdic_math.h"
#include "prdic_timespecops.h"
#include "prdic_fd.h"
#include "prdic_pfd.h"
#include "prdic_main_pfd.h"
#include "prdic_recfilter.h"
#include "prdic_types.h"
#include "prdic_procchain.h"
#include "prdic_shmtrig.h"
#include "prdic_inst.h"
#include "prdic_band.h"
#include "prdic_time.h"
#include "prdic_main.h"

const double mineval = 0.001;
const double maxeval = 2.0;

int
_prdic_procrastinate_PFD(struct prdic_inst *pip)
{
    double add_delay, eval;
    struct prdic_band *abp = pip->ab;
#if PRD_DEBUG
    static long long nrun = -1;

    nrun += 1;
#endif

    _prdic_do_procrastinate(pip, abp->add_delay_fltrd.lastval == mineval);

    eval = _prdic_PFD_get_error(&abp->detector.phase, &abp->last_tclk);

#if PRD_DEBUG
    fprintf(stderr, "run=%lld raw_error=%f filtered_error=%f add_delay=%f\n", nrun, eval,
      abp->loop_error.lastval, abp->add_delay_fltrd.lastval);
    fflush(stderr);
#endif

#if PRD_DEBUG
    fprintf(stderr, "error=%f\n", eval);
    fprintf(stderr, "last=%lld target=%lld\n", (long long)SEC(abp->last_tclk),
      (long long)SEC(abp->detector.phase.target_tclk));
    fflush(stderr);
#endif

    if (eval > 0) {
        eval = _prdic_sigmoid(eval);
        _prdic_recfilter_apply(&abp->loop_error, eval);
    } else {
        _prdic_recfilter_apply(&abp->loop_error, _prdic_sigmoid(-eval));
    }
    if (eval != 0.0) {
        add_delay = abp->add_delay_fltrd.lastval / (1.0 - eval);

        _prdic_recfilter_apply(&abp->add_delay_fltrd, add_delay);
        if (abp->add_delay_fltrd.lastval < mineval) {
            abp->add_delay_fltrd.lastval = mineval;
        } else if (abp->add_delay_fltrd.lastval > maxeval) {
            abp->add_delay_fltrd.lastval = maxeval;
        }
    }
    return (0);
}
