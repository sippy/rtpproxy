/*
 * Copyright (c) 2018-2019 Sippy Software, Inc., http://www.sippysoft.com
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

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"

struct dummy {
    struct {
        struct rtpp_refcnt *rcnt;
    } pub;
};

static struct dummy *
rtpp_rzmalloc_perf_ctor(void)
{
    struct dummy *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct dummy), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&free,
      pvt);
    return (pvt);

e0:
    return (NULL);
}

int
main(int argc, char **argv)
{
    long long i, j, k;
    struct dummy *dpbuf[1000];

    for (i = 0; i < 10000000; i++) {
        j = i % 1000;
        if (i >= 1000) {
            for (k = 0; k < 11; k++) {
                CALL_SMETHOD(dpbuf[j]->pub.rcnt, decref);
            }
        }
        dpbuf[j] = rtpp_rzmalloc_perf_ctor();
        for (k = 0; k < 10; k++) {
            CALL_SMETHOD(dpbuf[j]->pub.rcnt, incref);
        }
    }
    for (i = 0; i < 1000; i++) {
         for (k = 0; k < 11; k++) {
             CALL_SMETHOD(dpbuf[i]->pub.rcnt, decref);
         }
    }
    return (0);
}
