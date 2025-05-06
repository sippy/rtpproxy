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

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "prdic_main.h"
#include "elperiodic.h"
#include "prdic_timespecops.h"
#include "prdic_math.h"
#include "prdic_fd.h"
#include "prdic_pfd.h"
#include "prdic_recfilter.h"
#include "prdic_types.h"
#include "prdic_procchain.h"
#include "prdic_shmtrig.h"
#include "prdic_inst.h"
#include "prdic_band.h"
#include "prdic_time.h"
#include "prdic_sign.h"

void
_prdic_do_procrastinate(struct prdic_inst *pip, int skipdelay)
{
    struct timespec tsleep, tremain;
    int rval, nint;
    double add_delay;
    struct timespec eptime;

    if (pip->sip != NULL) {
        prdic_CFT_serve(pip->sip);
        prdic_sign_unblock(pip->sip);
    }
    if (skipdelay) {
        goto skipdelay;
    }

    add_delay = pip->ab->period * pip->ab->add_delay_fltrd.lastval;
    dtime2timespec(add_delay, &tremain);

    do {
        unsigned int nsigns;

        tsleep = tremain;
        memset(&tremain, '\0', sizeof(tremain));
        if (pip->sip != NULL) {
            nsigns = prdic_sign_getnrecv();
        }
        rval = nanosleep(&tsleep, &tremain);
        nint = (rval < 0 && errno == EINTR);
        if (pip->sip != NULL) {
            if (nint && nsigns == prdic_sign_getnrecv()) {
                /* Got some interrupt, but it was not *our* signal */
                break;
            }
            prdic_sign_block(pip->sip);
            prdic_CFT_serve(pip->sip);
            prdic_sign_unblock(pip->sip);
        }
    } while (nint && !timespeciszero(&tremain));

skipdelay:
    if (pip->sip != NULL) {
        prdic_sign_block(pip->sip);
    }
    getttime(&eptime, 1);

    timespecsub(&eptime, &pip->ab->epoch);
    timespecmul(&pip->ab->last_tclk, &eptime, &pip->ab->tfreq_hz);
}
