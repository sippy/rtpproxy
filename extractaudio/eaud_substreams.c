/*
 * Copyright (c) 2017 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdlib.h>
#include <stdint.h>

#include "rtp_info.h"
#include "session.h"

struct cnode *
eaud_ss_find(struct channels *ssp, struct channel *cp)
{
    struct cnode *cnp;

    MYQ_FOREACH(cnp, ssp) {
        if (cnp->cp == cp) {
            return (cnp);
        }
    }
    return (NULL);
}

int
eaud_ss_syncactive(struct channels *all_ssp, struct channels *act_ssp,
  int64_t csample, int64_t *nsample)
{
    struct cnode *cnp;
    int64_t min_nsample;
    int nadded;

    min_nsample = -1;
    nadded = 0;
    MYQ_FOREACH(cnp, all_ssp) {
        if (cnp->cp->skip > csample) {
            if (min_nsample < 0) {
                min_nsample = cnp->cp->skip;
            } else if (min_nsample > cnp->cp->skip) {
                min_nsample = cnp->cp->skip;
            }
            continue;
        }
        if (eaud_ss_find(act_ssp, cnp->cp) == NULL) {
            if (channel_insert(act_ssp, cnp->cp) < 0)
               return (-1);
            nadded += 1;
        }
    }
    *nsample = min_nsample;
    return (nadded);
}
