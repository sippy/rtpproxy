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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_pearson.h"
#include "rtpp_mallocs.h"

struct rtpp_pearson_perfect
{
    struct rtpp_pearson rp;
    uint8_t omap_table[256];
    rtpp_pearson_getval_t gv;
    void *gv_arg;
};

void
rtpp_pearson_shuffle(struct rtpp_pearson *rpp)
{
    int i;
    uint8_t rval;

    memset(rpp->rand_table, '\0', sizeof(rpp->rand_table));
    for (i = 1; i < 256; i++) {
        do {
            rval = random() & 0xff;
        } while (rpp->rand_table[rval] != 0);
        rpp->rand_table[rval] = i;
    }
}

uint8_t
rtpp_pearson_hash8(struct rtpp_pearson *rpp, const char *bp, const char *ep)
{
    uint8_t res;

    for (res = rpp->rand_table[0]; bp[0] != '\0' && bp != ep; bp++) {
        res = rpp->rand_table[res ^ bp[0]];
    }
    return res;
}

uint8_t
rtpp_pearson_hash8b(struct rtpp_pearson *rpp, const uint8_t *bp, size_t blen)
{
    uint8_t res;
    const uint8_t *ep;

    ep = bp + blen;
    for (res = rpp->rand_table[0]; bp != ep; bp++) {
        res = rpp->rand_table[res ^ bp[0]];
    }
    return res;
}

static void
compute_perfect_hash(struct rtpp_pearson_perfect *rppp)
{
    int i;
    const char *sval;
    uint8_t hval;

again:
    rtpp_pearson_shuffle(&rppp->rp);
    memset(rppp->omap_table, '\0', sizeof(rppp->omap_table));

    for (i = 0; rppp->gv(rppp->gv_arg, i) != NULL; i++) {
        sval = rppp->gv(rppp->gv_arg, i);
        hval = rtpp_pearson_hash8(&rppp->rp, sval, NULL);
        if (rppp->omap_table[hval] != 0) {
            goto again;
        }
        rppp->omap_table[hval] = i + 1;
    }
}

struct rtpp_pearson_perfect *
rtpp_pearson_perfect_ctor(rtpp_pearson_getval_t gv, void *gv_arg)
{
    struct rtpp_pearson_perfect *rppp;

    rppp = rtpp_zmalloc(sizeof(struct rtpp_pearson_perfect));
    if (rppp == NULL) {
        return (NULL);
    }
    rppp->gv = gv;
    rppp->gv_arg = gv_arg;

    compute_perfect_hash(rppp);
    return(rppp);
}

int
rtpp_pearson_perfect_hash(struct rtpp_pearson_perfect *rppp, const char *isval)
{
    int rval;
    const char *sval;

    rval = rppp->omap_table[rtpp_pearson_hash8(&rppp->rp, isval, NULL)] - 1;
    if (rval == -1) {
        return (-1);
    }
    sval = rppp->gv(rppp->gv_arg, rval);
    if (strcmp(isval, sval) != 0) {
        return (-1);
    }
    return (rval);
}

void
rtpp_pearson_perfect_dtor(struct rtpp_pearson_perfect *rppp)
{

    free(rppp);
}
