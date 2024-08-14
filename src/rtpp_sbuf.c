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

#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_mallocs.h"
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
#if !defined(RTPP_CHECK_LEAKS)
rtpp_sbuf_ctor(int ilen)
#else
_rtpp_sbuf_ctor(int ilen, void *memdeb_p, const struct rtpp_codeptr *mlp)
#endif
{
    struct rtpp_sbuf *sbp;

#if !defined(RTPP_CHECK_LEAKS)
    sbp = malloc(sizeof(struct rtpp_sbuf));
#else
    sbp = rtpp_memdeb_malloc(sizeof(struct rtpp_sbuf), memdeb_p, mlp);
#endif
    if (sbp == NULL)
        return (NULL);
    memset(sbp, '\0', sizeof(struct rtpp_sbuf));
#if !defined(RTPP_CHECK_LEAKS)
    sbp->bp = sbp->cp = malloc(ilen);
#else
    sbp->bp = sbp->cp = rtpp_memdeb_malloc(ilen, memdeb_p, mlp);
#endif
    if (sbp->bp == NULL) {
        free(sbp);
        return (NULL);
    }
    sbp->cp[0] = '\0';
    sbp->alen = ilen;
    return(sbp);
}

void
#if !defined(RTPP_CHECK_LEAKS)
rtpp_sbuf_dtor(struct rtpp_sbuf *sbp)
#else
_rtpp_sbuf_dtor(struct rtpp_sbuf *sbp, void *memdeb_p, const struct rtpp_codeptr *mlp)
#endif
{

#if !defined(RTPP_CHECK_LEAKS)
    free(sbp->bp);
    free(sbp);
#else
    rtpp_memdeb_free(sbp->bp, memdeb_p, mlp);
    rtpp_memdeb_free(sbp, memdeb_p, mlp);
#endif
}

int
#if !defined(RTPP_CHECK_LEAKS)
rtpp_sbuf_extend(struct rtpp_sbuf *sbp, int nlen)
#else
_rtpp_sbuf_extend(struct rtpp_sbuf *sbp, int nlen, void *memdeb_p, const struct rtpp_codeptr *mlp)
#endif
{
    void *nbp, *ncp;

    assert(nlen > sbp->alen);
#if !defined(RTPP_CHECK_LEAKS)
    nbp = realloc(sbp->bp, nlen);
#else
    nbp = rtpp_memdeb_realloc(sbp->bp, nlen, memdeb_p, mlp);
#endif
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

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

#define errx_ifnot(expr) \
    if (!(expr)) \
        errx(1, "`%s` check has failed in %s() at %s:%d", #expr, __func__, \
          __FILE__, __LINE__);


RTPP_MEMDEB_APP_STATIC;

int
rtpp_sbuf_selftest(void)
{
    struct rtpp_sbuf *sbp;
    int rval;
    const char *longtest = "INFO:GLOBAL:rtpp_proc_async_run: ncycles=2600 load=0.068641";

    RTPP_MEMDEB_APP_INIT();

    sbp = rtpp_sbuf_ctor(6);
    errx_ifnot(sbp != NULL);
    errx_ifnot(sbp->alen == 6);
    errx_ifnot(sbp->cp == sbp->bp);
    errx_ifnot(RS_ULEN(sbp) == 0);
    rval = rtpp_sbuf_write(sbp, "%d", 12345);
    errx_ifnot(rval == SBW_OK);
    errx_ifnot(sbp->cp[0] == '\0');
    errx_ifnot(strcmp(sbp->bp, "12345") == 0);
    errx_ifnot(RS_ULEN(sbp) == 5);
    rval = rtpp_sbuf_write(sbp, "%s", "F");
    errx_ifnot(rval == SBW_SHRT);
    errx_ifnot(sbp->cp[0] == '\0');
    errx_ifnot(strcmp(sbp->bp, "12345") == 0);
    errx_ifnot(RS_ULEN(sbp) == 5);
    errx_ifnot(rtpp_sbuf_extend(sbp, 7) == 0);
    errx_ifnot(RS_ULEN(sbp) == 5);
    errx_ifnot(strcmp(sbp->bp, "12345") == 0);
    rval = rtpp_sbuf_write(sbp, "%s", "F");
    errx_ifnot(rval == SBW_OK);
    errx_ifnot(RS_ULEN(sbp) == 6);
    errx_ifnot(strcmp(sbp->bp, "12345F") == 0);
    do {
        errx_ifnot(rtpp_sbuf_extend(sbp, sbp->alen + 1) == 0);
        rval = rtpp_sbuf_write(sbp, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
          longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest,
          longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest, longtest);
    } while (rval == SBW_SHRT);
    errx_ifnot(rval == SBW_OK);
    errx_ifnot(RS_ULEN(sbp) == 1446);
    errx_ifnot(sbp->alen == RS_ULEN(sbp) + 1);
    errx_ifnot(strncmp(sbp->bp, "12345F", 6) == 0);
    rval = RS_ULEN(sbp);
    rtpp_sbuf_reset(sbp);
    errx_ifnot(sbp->cp == sbp->bp);
    errx_ifnot(sbp->cp[0] == '\0');
    errx_ifnot(sbp->alen == rval + 1);
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
