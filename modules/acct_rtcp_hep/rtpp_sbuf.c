/*
 * Copyright (c) 2018 Sippy Software, Inc., http://www.sippysoft.com
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

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(RTPP_MODULE)
#include "rtpp_module.h"
#endif

#include "rtpp_sbuf.h"

int
rtpp_sbuf_write(struct rtpp_sbuf *sbp, const char *format, ...)
{
    va_list ap;
    int rlen, len;

    len = sbp->alen - RS_ULEN(sbp);
    assert(len > 0);
    va_start(ap, format);
    rlen = vsnprintf(sbp->cp, len, format, ap);
    va_end(ap);
    if (rlen < 0)
        return (SBW_ERR);
    if (rlen >= len) {
        sbp->cp[0] = '\0';
        return (SBW_SHRT);
    }
    sbp->cp += rlen;
    return (SBW_OK);
}

struct rtpp_sbuf *
rtpp_sbuf_ctor(int ilen)
{
    struct rtpp_sbuf *sbp;

    sbp = malloc(sizeof(struct rtpp_sbuf));
    if (sbp == NULL)
        return (NULL);
    memset(sbp, '\0', sizeof(struct rtpp_sbuf));
    sbp->bp = sbp->cp = malloc(ilen);
    if (sbp->bp == NULL) {
        free(sbp);
        return (NULL);
    }
    sbp->cp[0] = '\0';
    sbp->alen = ilen;
    return(sbp);
}

void
rtpp_sbuf_dtor(struct rtpp_sbuf *sbp)
{

    free(sbp->bp);
    free(sbp);
}

int
rtpp_sbuf_extend(struct rtpp_sbuf *sbp, int nlen)
{
    void *nbp, *ncp;

    assert(nlen > sbp->alen);
    nbp = realloc(sbp->bp, nlen);
    if (nbp == NULL)
        return (-1);
    sbp->alen = nlen;
    if (sbp->bp != nbp) {
        ncp = nbp + RS_ULEN(sbp);
        sbp->cp = ncp;
        sbp->bp = nbp;
     }
     return (0);
}

#if defined(rtpp_sbuf_selftest)
#include <stdint.h>
#include "rtpp_memdeb_internal.h"
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"

RTPP_MEMDEB_APP_STATIC;

int
rtpp_sbuf_selftest(void)
{
    struct rtpp_sbuf *sbp;
    int rval;
    const char *longtest = "INFO:GLOBAL:rtpp_proc_async_run: ncycles=2600 load=0.068641";

    RTPP_MEMDEB_APP_INIT();

    sbp = rtpp_sbuf_ctor(6);
    assert(sbp != NULL);
    assert(sbp->alen == 6);
    assert(sbp->cp == sbp->bp);
    assert(RS_ULEN(sbp) == 0);
    rval = rtpp_sbuf_write(sbp, "%d", 12345);
    assert(rval == SBW_OK);
    assert(sbp->cp[0] == '\0');
    assert(strcmp(sbp->bp, "12345") == 0);
    assert(RS_ULEN(sbp) == 5);
    rval = rtpp_sbuf_write(sbp, "%s", "F");
    assert(rval == SBW_SHRT);
    assert(sbp->cp[0] == '\0');
    assert(strcmp(sbp->bp, "12345") == 0);
    assert(RS_ULEN(sbp) == 5);
    assert(rtpp_sbuf_extend(sbp, 7) == 0);
    assert(RS_ULEN(sbp) == 5);
    assert(strcmp(sbp->bp, "12345") == 0);
    rval = rtpp_sbuf_write(sbp, "%s", "F");
    assert(rval == SBW_OK);
    assert(RS_ULEN(sbp) == 6);
    assert(strcmp(sbp->bp, "12345F") == 0);
    do {
        assert(rtpp_sbuf_extend(sbp, sbp->alen + 1) == 0);
        rval = rtpp_sbuf_write(sbp, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
          longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest,
          longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest);
    } while (rval == SBW_SHRT);
    assert(rval == SBW_OK);
    assert(RS_ULEN(sbp) == 1446);
    assert(sbp->alen == RS_ULEN(sbp) + 1);
    assert(strncmp(sbp->bp, "12345F", 6) == 0);
    rval = RS_ULEN(sbp);
    rtpp_sbuf_reset(sbp);
    assert(sbp->cp == sbp->bp);
    assert(sbp->cp[0] == '\0');
    assert(sbp->alen == rval + 1);
    rtpp_sbuf_dtor(sbp);

    rval = rtpp_memdeb_dumpstats(MEMDEB_SYM, 0);
    return (rval);
}
#endif /* rtpp_sbuf_selftest */

void
rtpp_sbuf_reset(struct rtpp_sbuf *sbp)
{

    sbp->cp = sbp->bp;
    sbp->cp[0] = '\0';
}
